# TES hardware backend reference map

> Research target: implementations that are useful for making TES provide **real, usable TEE / StrongBox-backed behavior**, not just changing a status string.
>
> Baseline rule for this project: when a genuine TEE/StrongBox exists, business key material and secure state stay in that hardware domain. TES may route, adapt versions, preserve delegated-key graphs and rebuild attestation/certificate presentation, but must not silently replace a hardware-owned key with a software-TA key in strict hardware mode.

## 1. What was surveyed

### AOSP / official Android architecture

Primary references:

- AOSP KeyMint Rust reference implementation  
  https://android.googlesource.com/platform/system/keymint/
- AOSP KeyMint device abstraction, Android 17 tag  
  https://android.googlesource.com/platform/system/keymint/+/refs/tags/android-17.0.0_r1/ta/src/device.rs
- Android security HAL architecture  
  https://android.googlesource.com/platform/hardware/interfaces/+/main/security/README.md
- KeyMint AIDL  
  https://android.googlesource.com/platform/hardware/interfaces/+/main/security/keymint/
- RKP HAL  
  https://android.googlesource.com/platform/hardware/interfaces/+/main/security/rkp/
- keystore2 source  
  https://android.googlesource.com/platform/system/security/+/refs/heads/main/keystore2/src/
- keystore2 km_compat  
  https://android.googlesource.com/platform/system/security/+/refs/heads/main/keystore2/src/km_compat/

The AOSP Rust reference implementation is the most useful checklist for a complete backend. A real device port must supply or deliberately omit these device abstractions:

- secure/monotonic time;
- root-key retrieval;
- attestation signing information;
- attestation IDs;
- RKP/DICE artefacts;
- SecureDeletionSecretManager;
- bootloader state;
- StorageKeyWrapper;
- trusted user presence;
- legacy keyblob conversion.

Important consequence for TES:

- in **strict hardware mode**, TES should not implement fake copies of these when the real KeyMint already owns them; forwarding to the exact TEE/StrongBox instance is the correct implementation;
- in a future **software compatibility backend**, these are the exact missing components that must be supplied before it can honestly claim semantic completeness.

AOSP also confirms that KeyMint, ISharedSecret and ISecureClock are a coordinated security-domain design. HardwareAuthToken authenticity relies on a per-boot shared HMAC known to secure components. TES must therefore not invent a second independent SharedSecret negotiation in strict hardware mode.

### keystore2 / km_compat

The current keystore2 tree has separate modules for:

- authorization;
- maintenance;
- super keys;
- shared-secret negotiation;
- remote provisioning;
- boot-level keys;
- legacy blob migration;
- km_compat.

km_compat is especially relevant to TES because it proves that Android already treats legacy Keymaster <-> modern KeyMint adaptation as a **stateful compatibility layer**, not a thin method rename. Example: older Keymaster implementations may consume zero bytes on update in certain block modes, so km_compat buffers incomplete updates rather than assuming modern semantics.

TES action:

1. use km_compat behavior as the reference whenever Android 10/11 Keymaster is wrapped behind our modern router;
2. do not add vendor-specific workarounds until the equivalent km_compat behavior has been checked;
3. add legacy-version fixture tests for update buffering, operation slots and certificate conversion.

---

## 2. StrongBox reference: JavaCardKeymaster

Repository:

- https://github.com/divegeek/JavaCardKeymaster
- Apache-2.0
- archived, but still one of the clearest public StrongBox implementations.

This project is valuable because it is not a certificate-spoofing module. It has a userspace HAL plus a JavaCard applet running in a separate secure element.

Important structures found in the source:

### Provisioned device state

KMKeymasterApplet defines explicit provisioning commands for:

- attestation key;
- attestation certificate data;
- attestation IDs;
- pre-shared secret;
- boot parameters;
- OEM lock state;
- version / patch levels.

That is a strong design lesson: a StrongBox backend has persistent **device state**, not merely a SecurityLevel enum.

### Shared HMAC / HAT

The applet implements:

- get HMAC sharing parameters;
- compute shared HMAC;
- a provisioned pre-shared secret;
- HardwareAuthToken parsing/verification;
- labels such as "KeymasterSharedMac" and "Auth Verification".

This reinforces our current strict-hardware choice: on a real device, HAT validation belongs inside the real TEE/StrongBox security domain. TES should observe health but not renegotiate the shared secret.

### Operations are security-element state

The HAL tracks StrongBox operation handles separately and explicitly clears StrongBox operations when the secure element resets or the applet upgrades.

TES action:

- keep the current exact StrongBox operation ownership model;
- add a reset/session epoch to hardware-mode operation wrappers so an SE/HAL restart invalidates stale operations deterministically;
- do not treat process-local operation count as authoritative for real StrongBox.

### Early boot and rollback

The JavaCard implementation has explicit early-boot state handling. It also explicitly rejects rollback-resistant keys when rollback protection is unavailable.

This is exactly the policy TES should keep:

- strict hardware mode forwards the real behavior;
- software mode must return ROLLBACK_RESISTANCE_UNAVAILABLE until a genuine SecureDeletionSecretManager/persistent secure store exists.

### Key blobs

generate/import/importWrappedKey are transported to the secure element and return opaque key blobs plus hardware characteristics. This is the correct ownership model for TES strict hardware mode: the router must never deserialize and recreate the private key in normal Android memory.

### Limitation that is useful to us

JavaCardKeymaster does not support every feature. It returns explicit unsupported/unimplemented errors rather than fabricating them. That behavior is preferable to a "green status" when the physical backend cannot guarantee the property.

---

## 3. AOSP Rust KeyMint vs current TES software TA

Current TES generation-mode/reference TA is derived from the same general KeyMint Rust architecture, but historically used placeholders such as:

- no SecureDeletionSecretManager;
- no StorageKeyWrapper;
- no real RPC artefacts;
- local/process state for some lifecycle semantics.

Therefore two different goals must remain separated:

### hardware mode

- real HAL owns keyBlob;
- real HAL owns private/secret key material;
- real HAL owns HAT verification, counters, clock, rollback, StorageKey;
- TES may patch/reissue certificates while preserving cryptographic parent/child relationships;
- missing physical hardware is a hard error.

### generation / compatibility mode

This is the place where a future complete software backend can implement the missing AOSP device traits. It must never be confused with a physically isolated TEE/StrongBox.

---

## 4. OhMyKeymint

Repository:

- https://github.com/qwq233/OhMyKeymint
- AGPL-3.0; do not copy code into TES. Reimplement ideas independently.

The useful part of OhMyKeymint is not merely certificate generation. It mirrors a much broader keystore2 state machine.

### Authorization and CE state

Relevant paths:

- src/keymaster/authorization.rs
- src/keymaster/super_key.rs
- src/keymaster/enforcements.rs
- injector/src/hook/rewrite/mirror.rs

It mirrors:

- onDeviceUnlocked;
- onDeviceLocked;
- onUserStorageLocked;
- weak/non-LSKF unlock expiry;
- CredentialEncrypted super-key availability;
- auth-bound storage policy.

This is important for TES **only when TES itself owns software keys**. For strict hardware keys, keystore2 already drives the genuine hardware KeyMint/authorization path, and TES should avoid creating a second state authority.

### RKP

Relevant paths:

- hal/src/rpc.rs
- src/keymint/rpc.rs
- ta/src/device.rs
- common/src/vintf.rs

OhMyKeymint models IRemotelyProvisionedComponent as a first-class HAL, not a boolean RKP switch. Its TA has dedicated RPC key derivation/context and CSR processing.

TES action:

- keep expanding the current typed RKP Binder path;
- model RKP by concrete IRPC instance and certificate type;
- keep the RKPD-provisioned opaque hardware key blob unchanged in strict hardware mode;
- scope certificate reissue to the associated hardware key, never replace the private key.

### VINTF

OhMyKeymint has full VINTF/AIDL instance resolution. We already independently adopted this design direction. Keep fixture coverage aligned with libvintf semantics.

### Injector health

Its recent work demonstrates why "library mapped" is not equivalent to "hook functional". TES already moved toward entry-ok -> hook-active -> control-connected -> config-acked. Keep that model.

---

## 5. TrickyStore OSS

Repository:

- https://github.com/beakthoven/TrickyStoreOSS
- GPL-3.0.

Important source:

- CertificateHack.kt
- interceptors/KeystoreInterceptor.kt

### What it does well

CertificateHack parses the existing hardware leaf, keeps the leaf public key, rebuilds the attestation extension and signs a replacement leaf under keybox material. It also contains compatibility handling for Android 11 devices where softwareEnforced/teeEnforced may be swapped.

KeystoreInterceptor demonstrates mature per-UID / per-package interception and old-keystore transaction handling.

### What it does *not* solve for TES

It is primarily an interception/certificate layer. It does not make a missing StrongBox processor exist and is not a reference for secure-element state, SharedSecret, StorageKey or rollback-resistant storage.

Its SECURITY.md is particularly instructive: when an app supplies another attest key, re-signing the child requires access to that attest key's private key; old approaches therefore generate/intercept a software attest key. That is precisely what TES **must not do in strict hardware mode**.

TES action:

- borrow the idea of robust attestation-extension parsing and legacy layout compatibility;
- do not borrow the "software-own the attest-key private key" solution for strict hardware;
- preserve a genuine hardware delegated A -> B chain even if this means some child fields cannot be rewritten.

---

## 6. Zygisk-KeystoreInjection

Repository:

- https://github.com/aviraxp/Zygisk-KeystoreInjection
- GPL-3.0, archived.

Important source:

- CustomKeyStoreSpi.java
- CustomKeyStoreKeyPairGeneratorSpi.java
- CertUtils.java

It installs a custom Java security provider / KeyStore SPI, delegates ordinary key access to the original keystore, and replaces certificate-chain presentation or generated keypair behavior for selected paths.

This is useful as an example of **application/API surface interception**, but it is deliberately above KeyMint. Its custom generator can create Java keypairs and synthesize a KeyDescription extension using normal-process cryptography.

TES conclusion:

- useful as a historical example of which Java API surfaces callers observe;
- not a TEE/StrongBox implementation;
- do not use it as the backend design for PR #4.

---

## 7. Tencent Soter

References:

- https://github.com/Tencent/soter
- client SDK plus public architecture documentation.

Soter is not just "another KeyMint tag".

The architecture has three levels:

- ATTK: device root key provisioned before shipment;
- ASK: app secure key;
- AuthKey: user-authenticated signing key.

The design documentation explicitly places key generation/storage and signing in TEE.

Two integration generations exist:

### pre-Treble

Soter installs/uses SoterKeyStoreProvider and custom Android keystore conventions. ASK/AuthKey generation uses specially encoded aliases / parameters and RSA-PSS.

### Treble

The SDK talks to com.tencent.soter.soterserver.ISoterService. Public AIDL includes:

- generateAppSecureKey;
- getAppSecureKey;
- generateAuthKey;
- getAuthKey;
- initSigh;
- finishSign;
- getDeviceId;
- getVersion.

OnePlus device trees also show a vendor.qti.hardware.soter@1.0 service and SoterService.apk.

TES consequence:

Soter support requires a separate adapter/service path. A complete implementation should route Soter ASK/AuthKey operations to a real TEE-backed primitive and preserve Soter's ATTK -> ASK -> AuthKey trust graph. Merely making Android KeyMint attestation pass is insufficient.

---

## 8. OnePlus / OPlus IFAA

Older OnePlus public device trees show:

- system_ext/priv-app/IFAAService/IFAAService.apk
- vendor.oneplus.hardware.ifaa@2.0-service
- HIDL IOneplusIfaa/default
- dedicated SELinux hwservice domains.

This establishes that IFAA is a separate vendor HAL/service surface, not just a KeyMint API alias.

TES action:

- discover the current OPlus Android 16 equivalent on the target device;
- intercept/bridge the real vendor service only after its transaction/API contract is mapped;
- use real TEE-backed signing/authentication under that service;
- do not report IFAA success merely because TEE KeyMint works.

---

## 9. OPlus FIDO / FIDO2 / fingerprint-pay / crypto engines

Current OPlus/OnePlus Android 16 firmware inventories expose dedicated services and client libraries such as:

- vendor.oplus.hardware.fido.fidoca@1.0-service
- vendor.oplus.hardware.fido.fido2ca@1.0-service
- vendor.oplus.hardware.biometrics.fingerprintpay@1.0-service
- vendor.oplus.hardware.cryptoeng@1.0-service
- vendor.oplus.hardware.hdcp service
- matching Java and NDK interface libraries.

Therefore the engineering-mode "FIDO key", "FIDO2 key", IFAA, HDCP and Crypto entries are not all read from IKeyMintDevice.

TES consequence:

- treat KeyMint as the common cryptographic foundation where appropriate;
- add separate OPlus vendor-service adapters for the components whose public contract is outside KeyMint;
- map service -> TA/key hierarchy before implementing;
- for each adapter require a functional operation (create/use/sign/session), not a status-only hook.

This is the next major research target after PR #4's core hardware KeyMint path.

---

## 10. RKP and "RKP Widevine"

AOSP RKP is intentionally reusable beyond KeyMint. Android U/v3 introduced CertificateType and the changelog explicitly describes values corresponding to certificate classes such as keymint/widevine in that generation.

Therefore the screenshot's "RKP Default" and "RKP Widevine" should not be treated as the same boolean.

TES action:

- enumerate concrete IRemotelyProvisionedComponent instances and RpcHardwareInfo;
- preserve the real secure-component key generation and CSR signing;
- separate certificate type / consumer;
- do not route Widevine provisioning through an ordinary KeyMint certificate-chain patch without proving the component contract.

---

## 11. Historical FrameworkPatch / BootloaderSpoofer / KeyAttestation

FrameworkPatch and BootloaderSpoofer are useful historically for identifying framework-level observation points, but the original repositories are no longer reliably available. TrickyStore OSS itself lists them as dead and relies on forks/mirrors.

KeyAttestation is useful as a verifier/parser corpus, not as a backend implementation.

TES action:

- use verifier projects to build adversarial tests;
- do not build new architecture around dead framework-patch techniques when we can intercept lower at KeyMint/keystore2.

---

## 12. Direct changes this research implies for TES

### Keep

The PR #4 direction is correct:

- strict hardware mode;
- real keyBlob ownership;
- exact TEE vs StrongBox binder identity;
- certificate-level security-level verification;
- hardware ATTEST_KEY ownership;
- delegated-chain preservation;
- typed RKP interception;
- side-effect-free SharedSecret/SecureClock health checks;
- hardware StorageKey/auth-bound/rollback routing.

### Add next

1. **Legacy Keymaster compatibility layer**
   - compare every method with AOSP km_compat;
   - add buffering/slot/certificate conversion tests.

2. **Hardware session epoch**
   - invalidate forwarded StrongBox operation wrappers when the secure element/HAL restarts;
   - model this separately from keystore2 PID epoch.

3. **RKP component matrix**
   - enumerate instance, version, uniqueId, certificate type and supported key count;
   - distinguish keymint/default vs widevine-style consumers where present.

4. **Strict-hardware conformance suite**
   - TEE and StrongBox separately:
     - EC generate/sign/verify/attest;
     - RSA sign/verify;
     - AES-GCM;
     - HMAC;
     - import;
     - wrapped import;
     - auth-bound use after biometric/LSKF;
     - StorageKey convert-to-ephemeral;
     - early boot;
     - usage/rate limits where supported;
     - ATTEST_KEY parent -> child verification;
     - RKP-provisioned ATTEST_KEY -> child verification;
     - restart/reconnect behavior.

5. **OPlus service map**
   - current Android 16 IFAA;
   - fidoca;
   - fido2ca;
   - fingerprintpay;
   - cryptoeng;
   - HDCP;
   - Soter / equivalent path.
   Each gets a real functional adapter, not an engineering-mode status hook.

6. **Software compatibility backend, later**
   - if retained, implement the missing AOSP device traits explicitly;
   - it remains a compatibility backend, never a physical StrongBox claim.

---

## 13. Sources whose code must not be copied blindly

Licensing / architecture constraints:

- AOSP KeyMint / keystore2: Apache-2.0.
- JavaCardKeymaster: Apache-2.0.
- TrickyStoreOSS: GPL-3.0.
- Zygisk-KeystoreInjection: GPL-3.0.
- OhMyKeymint: AGPL-3.0.
- Tencent Soter public project: follow its repository license terms; its documentation describes a vendor/TEE protocol whose server/device provisioning assumptions cannot be reproduced by simply copying client code.

For GPL/AGPL projects, use them for behavioral research and independently implement the necessary design in TES rather than copying source across incompatible project boundaries.

## Bottom line

The broad survey supports one architecture:

**TES strict hardware mode should be a security-domain-preserving compatibility hypervisor around genuine KeyMint/StrongBox, not a second fake secure world.**

Certificate interception projects teach us how callers observe and verify results. AOSP and JavaCard StrongBox teach us what the real secure backend must own. OhMyKeymint teaches us which keystore2/RKP/state transitions must be mirrored when software keys are owned locally. Soter/IFAA/FIDO show that several OEM "Key" rows are separate security services whose key hierarchy ultimately needs its own adapter and functional test.

That is the implementation model to use for the next TES stages.
