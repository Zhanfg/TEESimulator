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


---

## 14. OnePlus / OPlus Key Status -> real backend map

This section maps the ColorOS/OPlus engineering-mode Key Status surface to the actual public
service/TA evidence found in current OnePlus/OPlus trees. It is deliberately a backend map, not a
plan to force every row to "success".

### 14.1 CryptoEng is a real independent vendor command channel

Public OPlus framework source exposes:

- Binder service: `vendor.oplus.hardware.cryptoeng.ICryptoeng/default`
- method: `byte[] cryptoeng_invoke_command(byte[] request)`

Public `CryptoEngManager.CommandId` values include:

| Command | ID | Meaning visible in public framework code |
|---|---:|---|
| Google attestation write | `0x03` | provision/write Google attestation material |
| Google attestation verify | `0x04` | verify Google attestation material |
| Find-phone status | `0x12` | unrelated device-security status |
| Generate PKI cert | `0x18` | generate PKI certificate |
| Verify PKI cert | `0x19` | verify PKI certificate |
| HDCP key write | `0x33` | provision HDCP key material |
| HDCP key verify | `0x34` | verify HDCP key material |
| Cleanup | `0x35` | vendor cleanup command |
| Get secure type | `0x36` | query secure implementation/type |
| Widevine support | `0x3b` | query Widevine support |
| Crypto support | `0x3c` | query crypto-engine support |
| Engineer | `0x5a` | engineering command family |

Evidence also shows `librpmbengclient.so` shipped beside cryptoeng-related vendor components on
OPlus/OnePlus generations, and older builds label the cryptoeng service as a Keybox/TEE component.

**Important boundary:** these numeric command IDs identify the command family only. The payload and
response schemas are vendor protocol. TES must not invent them. Before implementing a strict adapter,
recover the target-device packet format from the generated NDK library / stock service binary or
controlled tracing.

### 14.2 Key Status row mapping

| Engineering-mode row | Real backend evidence | TES target layer | Current confidence |
|---|---|---|---|
| RPMB key | `librpmbengclient.so`, QTI/OPlus secure storage users, CryptoEng/IFAA adjacency | RPMB / vendor secure-storage bridge | High that it is separate from generic KeyMint; exact row protocol still unresolved |
| SOTER key | `SoterService.apk` + `vendor.qti.hardware.soter-service` | Qualcomm/OEM Soter service + TA | High |
| IFAA key | `IFAAService`, fingerprintpay HAL, `libifaa_factory.so`, `librpmbengclient.so` | OPlus fingerprint-pay / IFAA bridge | High |
| Crypto key | CryptoEng command `0x3c` plus vendor cryptoeng TA/service | OPlus CryptoEng bridge | High |
| Widevine L1 key | CryptoEng support query `0x3b` plus independent DRM/Widevine secure stack | DRM/cryptoeng coordination, not IKeyMintDevice | High for separation; exact row test must be traced |
| HDCP key | CryptoEng write/verify `0x33/0x34`; some trees also expose OPlus HDCP HAL | HDCP/CryptoEng vendor bridge | High |
| Attestation / Google key | CryptoEng `0x03/0x04` plus Android KeyMint attestation/provisioning | QTI KeyMint + CryptoEng provisioning boundary | High |
| FIDO key | `vendor.oplus.hardware.fido.fidoca.IFidoDaemon/default`, `libfido_factory.so`, secure TA firmware | FIDO vendor service / TA adapter | High |
| PKI cert | CryptoEng `0x18/0x19` | CryptoEng PKI command adapter | High |
| PKI Group cert | no public top-level command ID identified yet | unresolved CryptoEng subcommand / separate OEM PKI surface | **Unresolved: trace target firmware before implementation** |
| FIDO2 key | `vendor.oplus.hardware.fido.fido2ca.IFidoDaemon/default`, `libfido2_factory.so`, `fidoctap` secure TA | FIDO2 vendor service / CTAP TA adapter | High |
| RKP default | Android `IRemotelyProvisionedComponent`, TEE/KeyMint certificate class | per-level RKP overlay preserving opaque hardware keyBlob | High |
| RKP Widevine | Android RKP supports non-KeyMint certificate consumers in newer generations; exact OPlus wiring is device-specific | RKP component/certificate-type adapter | Medium; enumerate target `IRPC` instances and certificate types |
| StrongBox key | NXP `android.hardware.security.keymint3-service.strongbox.nxp` on SM8750 trees; product family also contains Thales StrongBox support | real StrongBox backend adapter | High |

### 14.3 OnePlus 13 / SM8750 concrete service topology

Public OnePlus SM8750 trees show all of the following in the platform family:

- `android.hardware.security.keymint-service-qti` / QTI TEE KeyMint;
- `android.hardware.security.keymint3-service.strongbox.nxp`;
- `android.hardware.weaver-service.nxp`;
- NXP StrongBox UID / file ownership entries;
- Thales StrongBox UID and service binary entries on the wider product family;
- `vendor.qti.hardware.soter-service`;
- OPlus fingerprint-pay / IFAA service and libraries;
- OPlus FIDO and FIDO2 daemon interfaces;
- `libGPTEE_vendor.so`;
- `libesesbprovision.so`;
- `librpmbengclient.so`.

The correct TES discovery model for this family is therefore:

```
keystore2
  |
  +-- IKeyMintDevice/default  -> QTI TEE KeyMint
  |      +-- TEE SharedSecret / SecureClock
  |      +-- TEE RKP
  |
  +-- IKeyMintDevice/strongbox -> NXP (or product-specific Thales) secure element
         +-- StrongBox SharedSecret
         +-- StrongBox RKP, when exposed
         +-- NXP Weaver is a related secure-element service, not a KeyMint alias

OPlus vendor secure services
  |
  +-- ICryptoeng/default -> cryptoeng secure TA / RPMB / provisioning commands
  +-- fingerprintpay     -> IFAA / payment TA / RPMB
  +-- Soter service      -> Qualcomm Soter TA
  +-- fidoca             -> FIDO secure TA
  +-- fido2ca            -> FIDO2/CTAP secure TA
```

### 14.4 What to borrow from earlier modules

**KeystoreInjection / Framework-level projects**

Borrow:
- Java API observation points;
- provider compatibility;
- certificate-chain edge cases.

Do not borrow:
- process-local RSA/EC key generation as a hardware backend;
- fabricated KeyDescription security levels.

**TrickyStoreOSS**

Borrow:
- caller scoping;
- alias/domain/namespace/grant lifecycle;
- cache invalidation;
- operation error compatibility;
- certificate parsing and legacy-Keymaster tolerance.

Do not borrow for strict hardware:
- normal-filesystem private-key persistence;
- software operation engine presented as hardware.

**OhMyKeymint**

Borrow independently:
- keystore2 authorization / maintenance state mirroring;
- transaction-layout compatibility;
- VINTF instance resolution;
- restart/race handling;
- RKP state-machine ideas.

Do not copy AGPL source, and do not treat its host software backend as physical TEE/StrongBox.

**AOSP km_compat**

This is the most important compatibility precedent:
- preserve the real hardware identity;
- mark software-emulated blobs separately;
- route every later operation back to the backend that created the blob;
- propagate lifecycle signals to all relevant backends;
- never software-emulate wrapped-key import or StorageKey conversion just to fill a feature gap;
- classify authorizations by the layer that actually enforces them.

TES should follow this model whenever compatibility fallback is unavoidable.

### 14.5 Research tasks still open before vendor adapters are written

Do not start a strict OPlus vendor adapter until these are resolved from the target device or a
matching stock dump:

1. `ICryptoeng` request/response packet layouts for the command IDs above.
2. Exact RPMB-key status command and whether it is a CryptoEng subcommand or direct
   `librpmbengclient` path.
3. PKI Group certificate command/subcommand and certificate store.
4. Current Android 16 `fidoca/fido2ca IFidoDaemon` transaction schema.
5. Soter service/HAL transaction version on the target build and ATTK/ASK/AuthKey persistence path.
6. Exact `IRemotelyProvisionedComponent` instances, `RpcHardwareInfo.uniqueId`, version and
   certificate-type support for TEE, StrongBox and any Widevine consumer.
7. Whether the target SKU selects NXP or Thales StrongBox at runtime; never infer this only from a
   package being present in the product tree.

Until those are known, TES should keep the vendor paths untouched rather than replace them with
software responses.

### 14.6 Acceptance rule for each Key Status item

A row may be called **implemented by TES** only when the real operation behind it succeeds through the
expected secure domain. Examples:

- StrongBox: generate -> begin/update/finish -> verify -> provenance -> reboot persistence.
- RKP: hardware key generation -> CSR/provisioning -> assigned cert -> delegated child verification.
- Soter: real ATTK/ASK/AuthKey hierarchy and sign/verify through Soter TA.
- IFAA: real fingerprint-pay/IFAA command reaches secure TA and authentication/signature succeeds.
- FIDO/FIDO2: real vendor daemon reaches the secure TA and completes an authenticator operation.
- PKI: real CryptoEng PKI certificate generate/verify path succeeds.
- HDCP/Widevine: the genuine provisioning/verification operation succeeds in its DRM/vendor domain.
- RPMB: only read/functional verification of already-provisioned secure storage; TES must never
  auto-provision or overwrite a device RPMB key during normal operation.

A green UI string by itself is never acceptance evidence.


### 14.7 Additional protocol clues from public compatibility projects

These are **reverse-engineering clues, not target-device specifications**. They are recorded so a
OnePlus 13 trace can confirm or reject them.

#### Soter Binder transaction map

The public D-Soter interceptor identifies
`com.tencent.soter.soterserver.ISoterService` transactions 1..13 as:

1. generateAppSecureKey
2. getAppSecureKey
3. hasAskAlready
4. generateAuthKey
5. removeAuthKey
6. getAuthKey
7. removeAllAuthKey
8. hasAuthKey
9. initSigh / initialize signing session
10. finishSign
11. getDeviceId
12. getVersion
13. getExtraParam

D-Soter then forges these replies in-process. TES must **not** reuse the forged-data design. The value
of this project is the Binder transaction inventory and the fact that interception inside
`com.tencent.soter.soterserver` sees the complete SDK-facing surface.

For a real TES Soter adapter, use the same transaction map only after matching it to the target
SoterService build, and forward the operations into the actual QTI/OEM Soter TA so ATTK/ASK/AuthKey
private material and counters remain in secure world.

#### CryptoEng KMS/TA framing

A public ColorOS compatibility proxy reports a second framing carried through
`ICryptoeng.cryptoeng_invoke_command(byte[])`, separate from the public MethodBuffer-style command
family:

```
u32be command_id
u32be payload_len
u32be parameter_count
repeat parameter_count:
    u32be type
    u32be length
    byte[length] value
```

That project observed command IDs in the `0x320..0x3ff` range and labels:

- `0x321`: TEE-purpose-supported capability query;
- `0x337`: TA-availability query;
- parameter type `0x2d4` as the boolean result in those two probes.

It also documents that later authenticated/KMS operations use the same secure-service path.

**Do not hard-code these into TES yet.** The project is a compatibility proxy, not OEM source. Before
TES implements them, capture the actual OnePlus 13 request/response bytes or inspect the matching
stock `ICryptoeng` client/service binaries. If they match, implement the parser as a bounded typed
codec and forward unknown commands byte-for-byte to the genuine service.

This is a useful design precedent for all vendor adapters: **decode only proven commands; passthrough
everything else; never replace the real secure backend merely because the envelope is understood.**


---

## 15. Cross-vendor backend evidence: do not hard-code TES to QTI + NXP

The OnePlus 13 path is the immediate target, but the backend abstraction must stay vendor-neutral.
Public Samsung/Exynos Trustonic KeyMint code provides a useful independent implementation check.

### Samsung / Trustonic KeyMint

Public Samsung SLSI/Trustonic KeyMint HAL code exposes separate Binder frontends for:

- `IKeyMintDevice`;
- `ISharedSecret`;
- `ISecureClock`;
- `IRemotelyProvisionedComponent`.

All four share one underlying `TrustonicKeymintDeviceImpl`, which means they are different Android
interfaces over the same secure-world domain.

Observed behavior:

- `generateKey` / `importKey` pass the optional hardware `AttestationKey` blob and issuer into
  the secure implementation and return the opaque key blob/characteristics/certificate chain;
- `begin` forwards the genuine `HardwareAuthToken` into the same implementation and returns a
  backend operation handle;
- `deviceLocked` and `earlyBootEnded` are real secure-backend lifecycle commands;
- `ISharedSecret.getSharedSecretParameters/computeSharedSecret` call the backend HMAC-sharing
  implementation;
- `ISecureClock.generateTimeStamp` calls the backend timestamp generator and returns its MAC;
- RKP returns a secure-world private-key handle and MACed public key, then builds the CSR through the
  same Trustonic implementation.

This confirms a general TES model:

```
BackendDomain
  +-- KeyMintDevice
  +-- SharedSecret
  +-- SecureClock
  +-- RKP
  +-- lifecycle/session epoch
```

These interfaces should be resolved and health-tracked **as a domain**, not as four unrelated Binder
services.

### StrongBox vendor neutrality

NXP JavaCard is the concrete OnePlus 13-class reference, but public Thales JavaCard KeyMint HAL work
shows the same architectural class: Android Binder/HAL frontend -> APDU/SE transport -> isolated
applet state.

TES therefore needs a `StrongBoxBackend` contract whose implementation is selected from service
identity/VINTF/runtime evidence, e.g.:

- NXP;
- Thales;
- future vendor/eSE implementations.

The contract must not contain NXP-only names above the adapter layer.

### QTI source visibility boundary

Current Qualcomm KeyMint implementation details are mostly proprietary on production devices. Public
device trees expose the service names/libraries, and provisioning tools expose parts of the QSEE
command path, but TES must not infer undocumented QTI internals from filenames alone.

For QTI strict mode:
- treat `IKeyMintDevice/default`, the matching SharedSecret/SecureClock/RKP services, and their
  observed behavior as authoritative;
- use AOSP VTS plus on-device conformance to define correctness;
- keep QSEE/keymaster provisioning commands out of normal runtime routing unless their exact stock
  contract and safety properties are established.

### Abstraction consequence

Do not encode:

```
if OnePlus -> QTI TEE + NXP StrongBox
```

in the core router.

Encode:

```
discover BackendDomain instances
verify identity + functionality + provenance
bind profile to exact domain
route opaque blobs and lifecycle back to that domain
```

Then the OnePlus adapter may prefer QTI/NXP based on actual discovered services, while Samsung,
Pixel/Trusty, Thales, legacy Keymaster or future secure-VM backends can implement the same domain
contract without changing key ownership rules.


---

## 16. Additional interception, verification and legacy-compat references

This pass widened the survey beyond backend implementations themselves. These projects are useful for
defining observable behavior, verifier expectations and safe compatibility boundaries.

### 16.1 BootloaderSpoofer / framework leaf-hack lineage

A maintained BootloaderSpoofer fork shows two distinct approaches:

1. **hardware leaf rewrite** — let the real AndroidKeyStore generate the key, intercept
   `engineGetCertificateChain`, rewrite RootOfTrust/attestation fields and re-sign the leaf under
   keybox material;
2. **full generated mode** — create RSA/EC keys in AndroidOpenSSL/Conscrypt, synthesize the complete
   attestation certificate and cache it by alias.

TES lesson:

- the first model is a useful historical precedent for *certificate-surface rewriting around a real
  key*;
- the second model is explicitly a software-key path and belongs only to TES compatibility/generation
  mode, never strict hardware mode;
- provider/framework interception is an observation surface, not proof of TEE/StrongBox ownership.

FrameworkPatch / FrameworkPatcherGO belong to the same historical family: framework-level
AndroidKeyStore hooks can make a caller observe a rewritten chain, but they do not create the lower
KeyMint security domain. Keep them as compatibility references, not backend references.

### 16.2 KeyAttestation as an executable user-space oracle

`vvb2060/KeyAttestation` is more useful than a simple certificate viewer. Its current code exercises:

- normal and StrongBox key generation;
- optional persistent ATTEST_KEY aliases and delegated attestation;
- device-ID attestation;
- StrongBox unavailable/error behavior;
- RKP capability checks;
- `RpcHardwareInfo` and CBOR `DeviceInfo` parsing;
- RKP certificate acquisition and provisioning error classes.

This makes it an excellent independent device-level acceptance oracle for TES after VTS-like tests.
TES should be able to pass its TEE/StrongBox/delegated/RKP flows through KeyAttestation without relying
on app-specific exceptions.

### 16.3 GrapheneOS Auditor / AttestationServer as a verifier oracle

GrapheneOS Auditor and AttestationServer descend from Google's Android key-attestation verifier code
and independently parse:

- attestationVersion / keymasterVersion;
- attestationSecurityLevel / keymasterSecurityLevel;
- RootOfTrust;
- softwareEnforced / teeEnforced authorization lists;
- attestation application ID;
- challenge and unique ID;
- certificate-chain continuity and public-key identity.

Auditor also deliberately uses fresh hardware-backed keys plus a persistent hardware-backed signing
key and pins verified-boot / patch-level state over time.

TES lesson:

- do not validate only "certificate parses";
- strict hardware acceptance should include a server-style independent verification pass;
- preserve challenge, SPKI, delegated-parent signature relationships and authorization placement;
- use an external verifier to catch chain constructions that look plausible locally but are
  cryptographically inconsistent.

### 16.4 Thales JavaCard KeyMint confirms StrongBox domain bundling

The public Thales JavaCard KeyMint 5.0 HAL advertises, for the same `strongbox` instance:

- `IKeyMintDevice/strongbox`;
- `IRemotelyProvisionedComponent/strongbox`;
- `ISharedSecret/strongbox`.

This independently confirms the NXP lesson: StrongBox should be modeled as one backend domain exposing
multiple Android interfaces over one isolated secure element, not as a KeyMint-only device.

TES implication:

```
StrongBoxBackendDomain
  identity / service epoch
  KeyMintDevice
  SharedSecret
  SecureClock when exposed
  RKP
  operation/session state
```

The adapter may be NXP, Thales or another vendor; the router above it should not contain vendor names.

### 16.5 AOSP km_compat gives a precise ownership-marker precedent

Current keystore2 `km_compat` uses explicit magic prefixes to distinguish:

- `pKMblob\x00` — underlying hardware Keymaster-owned blob;
- `pKMblob\x01` — software-emulated blob.

Its higher-level wrapper similarly wraps only software-emulated current-version features and routes
future `begin`, `upgradeKey`, `deleteKey` and `getKeyCharacteristics` according to blob
ownership.

Crucially:

- `importWrappedKey` always stays on the real backend because the wrapping key is likely
  hardware-bound;
- `convertStorageKeyToEphemeral` always stays on the real backend;
- lifecycle signals such as `deviceLocked` / `earlyBootEnded` are propagated to the relevant
  devices.

TES should copy this **ownership discipline**, not the exact prefix format. A future TES versioned
envelope should make backend ownership unambiguous and migration-safe.

### 16.6 Tencent Soter exact public API surface

Tencent's public `ISoterService.aidl` confirms the service contract directly:

1. generateAppSecureKey
2. getAppSecureKey
3. hasAskAlready
4. generateAuthKey
5. removeAuthKey
6. getAuthKey
7. removeAllAuthKey
8. hasAuthKey
9. initSigh
10. finishSign
11. getDeviceId
12. getVersion
13. getExtraParam

The non-Treble implementation also exposes the historical AndroidKeyStore integration:
`PURPOSE_SOTER_ATTEST_KEY` creates ASK material and RSA-PSS signs with private keys retrieved from
the Soter provider.

This strengthens the TES design rule:

- Soter is a complete key hierarchy and signing service;
- a real adapter must preserve ATTK/ASK/AuthKey secure ownership and session semantics;
- hooking only the engineering-page status or returning fabricated AIDL parcels is not an
  implementation.

### 16.7 Broader research coverage reached in this pass

The reference set now includes all of these categories:

- **real TEE / KeyMint:** AOSP Rust KeyMint, Trusty KeyMint, Samsung/Trustonic, Qualcomm production
  topology;
- **real StrongBox:** NXP JavaCard, Thales JavaCard / Ready SE;
- **legacy compatibility:** AOSP Keymaster HIDL + keystore2 `km_compat`;
- **attestation/keystore interception:** TrickyStore, TrickyStoreOSS, BootloaderSpoofer,
  Zygisk-KeystoreInjection, FrameworkPatch lineage;
- **full software keystore replacement/state modeling:** OhMyKeymint;
- **verification oracles:** AOSP VTS/CTS, KeyAttestation, GrapheneOS Auditor/AttestationServer;
- **OEM security services:** Tencent Soter, OPlus IFAA/fingerprintpay, FIDO/FIDO2, CryptoEng,
  RPMB, Widevine/HDCP;
- **remote provisioning:** per-level Android RKP implementations and user-space RKP verification.

That is broad enough to stop designing TES from any single predecessor. The implementation rule is now:

> use secure-backend projects to define ownership and lifecycle; use compatibility projects to define
> routing/version behavior; use interception projects to identify observation surfaces; and use
> independent verifiers to decide whether the resulting TEE/StrongBox behavior is actually coherent.
