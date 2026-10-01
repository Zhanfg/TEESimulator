# TES TEE / StrongBox reference implementation map

> Status: 2026-10-01 research pass 1  
> Branch: `feat/tee-strongbox-backends`

## 1. TES definition used by this work

TES is not a status-spoofing module and a software process must never be presented as a physical
StrongBox.

For a selected caller, TES provides a coherent KeyMint/Keystore security environment:

- when a genuine TEE or StrongBox backend exists, the business key blob, private/secret material,
  HAT enforcement, secure clock, rollback/usage state and storage-key lifecycle remain in that
  backend;
- TES may route calls, bridge platform/vendor API differences and transform attestation certificates,
  but it must not silently move a strict-hardware key into the in-process reference TA;
- TEE and StrongBox are separate backend instances/state domains, not a single backend plus a
  `SecurityLevel` label;
- OEM payment/security services (Soter, IFAA, FIDO, cryptoeng, DRM, RPMB, etc.) are separate
  security services when the device implements them that way. They are not to be forced into
  `IKeyMintDevice` merely because an engineering page calls them "keys".

The existing `generation` mode remains a compatibility/software-TA mode. The new `hardware` mode
is intentionally stricter.

---

## 2. Reference implementations and what they actually teach us

| Reference | Actual layer | Useful pattern for TES | Do **not** copy as a hardware claim |
| --- | --- | --- | --- |
| AOSP `platform/system/keymint` | KeyMint reference TA/device abstraction | clean separation of crypto, root keys, boot state, SecureDeletionSecretManager, StorageKeyWrapper, SharedSecret/HAT, SecureClock and RKP | host/file-backed implementations are reference mechanisms, not physical secure storage |
| AOSP keystore2 `km_compat` | compatibility wrapper above old Keymaster/KeyMint | explicit key-blob ownership marker; route every later operation by original owner; migrate old blobs on upgrade | do not infer ownership from a security-level string |
| Android Ready SE / JavaCard KeyMint | real StrongBox/eSE design | independent applet + HAL, independent operation pool, SharedSecret negotiation, boot/root-of-trust state, keyblob versioning, RKP provisioning | StrongBox is not "TEE with level=2" |
| TrickyStoreOSS | keystore2 Binder interception / response storage | broad keystore2 lifecycle coverage: security levels, aliases/namespaces, grants, metadata, createOperation, cache/persistence | generated software keys/metadata are not evidence of hardware ownership |
| Zygisk-KeystoreInjection | Java Security Provider / KeyStoreSpi | shows the highest-level interception surface and certificate-chain replacement | provider-only injection can return a chain for a key that AndroidKeyStore does not truly own |
| BootloaderSpoofer / leaf-hack style implementations | certificate/attestation rewrite | real hardware key + rewritten leaf is materially stronger than fully generated fake key | cert generation alone does not make `KeyInfo.isInsideSecureHardware()` true |
| OhMyKeymint public master | keystore2/KeyMint replacement + state services | authorization/maintenance mirroring, CE state, RKP plumbing, persistence discipline, VINTF/Binder coverage | filesystem SDD is not real rollback-resistant storage |
| ITxiao6666/OhMyKeymint `soter-ta` | Qualcomm/OPlus Soter AIDL replacement | concrete Soter transaction map, persistent ASK/AuthKey/session state, OnePlus 13 transaction captures, cryptoeng/engineering-mode interaction | software biometric counters are only a fallback model, not equivalent to secure-world fingerprint TA |
| Tencent Soter | OEM payment/authentication design | ATTK -> ASK -> AuthKey hierarchy and TEE ownership model | Soter is not a KeyMint tag |
| OPlus/QTI device blobs | real OEM service topology | tells TES where a capability really lives: KeyMint, QSEE TA, fingerprintpay, FIDO daemon, DRM, RPMB, etc. | do not turn an engineering-mode boolean into the source of truth |

### Primary source links

- AOSP KeyMint: https://android.googlesource.com/platform/system/keymint/
- AOSP keystore2 km_compat: https://android.googlesource.com/platform/system/security/+/refs/heads/main/keystore2/src/km_compat/
- Android Ready SE: https://android.googlesource.com/platform/external/libese/+/refs/heads/main/ready_se/
- Ready SE overview: https://developers.google.com/android/security/android-ready-se
- TrickyStoreOSS: https://github.com/beakthoven/TrickyStoreOSS
- Zygisk-KeystoreInjection: https://github.com/aviraxp/Zygisk-KeystoreInjection
- OhMyKeymint: https://github.com/qwq233/OhMyKeymint
- OnePlus-13-specific Soter work: https://github.com/ITxiao6666/OhMyKeymint
- Tencent Soter: https://github.com/Tencent/soter

License note: OhMyKeymint is AGPL-3.0. TES must use independently implemented ideas/protocol facts, not copy
AGPL source into this GPL tree without an explicit licensing decision.

---

## 3. AOSP patterns that should become TES invariants

### 3.1 Explicit backend ownership on every key blob

`km_compat` prefixes blobs to remember whether the real Keymaster or software KeyMint created them,
then routes `begin`, `upgradeKey`, `deleteKey`, `getKeyCharacteristics`, etc. back to the same
owner. It also contains migration logic for blobs created before/through old compatibility wrappers.

TES currently has a software marker but the long-term model should be a versioned ownership envelope:

```text
TES blob envelope
  magic + version
  backend = software-ta | real-tee | real-strongbox | legacy
  original/raw keyBlob
  optional migration metadata
  integrity/authentication tag for TES-owned envelope data
```

A raw genuine HAL blob must remain byte-for-byte usable by its HAL when strict hardware mode does not
need an envelope. Migration code must distinguish legacy TES software blobs from genuine historical
hardware blobs.

### 3.2 StrongBox is a separate backend

Ready SE KeyMint demonstrates the architectural boundary:

```text
Android Keystore / keystore2
        |
        +-- TEE IKeyMintDevice ----------> TEE TA / secure OS
        |
        +-- StrongBox IKeyMintDevice ----> StrongBox HAL -> eSE/iSE applet
                                      +--> its own SharedSecret/RKP/state
```

TES therefore must keep separate:
- backend identity;
- operation capacity/pool;
- hardware-info and supported algorithms;
- SharedSecret/SecureClock evidence;
- RKP instance/capability;
- lifecycle/availability;
- attestation version and provenance.

A missing StrongBox cannot be upgraded into a physical StrongBox by the in-process TA.

### 3.3 SharedSecret/HAT must remain in the real trust domain

The AOSP KeyMint abstraction expects an auth-bound backend either to share a secure-world HMAC secret
with authenticators directly or to participate in `ISharedSecret` joint derivation. Strict hardware
TES therefore should not renegotiate the system secret. The genuine HAL already participates in
Android's boot-time negotiation; TES should forward the real key operation and leave HAT validation to
that HAL.

Read-only health/provenance checks are fine. Re-running the N-party negotiation from TES is not.

### 3.4 Secure deletion / rollback state is not ordinary filesystem persistence

AOSP models secure deletion separately. OhMyKeymint's host SDD implementation is useful for slot
allocation, corruption handling and persistence mechanics, but it explicitly stores host state under
`/data/misc/keystore`.

For TES:
- strict hardware rollback/usage-limited keys must stay in real KeyMint;
- filesystem-backed SDD may only be used by an explicitly software compatibility backend;
- RPMB/eSE-backed state should be bridged only when a real OEM interface exists and semantics are
  understood.

---

## 4. Keystore interception lessons

### TrickyStoreOSS

Useful coverage to audit against TES:
- `IKeystoreService` and per-`IKeystoreSecurityLevel` separation;
- `getKeyEntry`, `updateSubcomponent`, grant/ungrant and namespaces;
- `generateKey`, `importKey`, `createOperation`;
- persistent alias/metadata lifecycle;
- service/transaction-version quirks.

TES should compare its interception surface to these flows, but strict hardware mode should not copy
TrickyStore's software-key generation model.

### Zygisk-KeystoreInjection and cert-generation approaches

These are valuable counterexamples. They can install/replace a provider and synthesize a valid-looking
certificate chain while the private key is not genuinely backed by AndroidKeyStore. This is exactly
why strict hardware TES is implemented below provider level and validates both:
- the real returned blob / KeyCharacteristics;
- attestation-level provenance when KeyDescription exists.

---

## 5. OnePlus 13 / OPlus security topology

### 5.1 OnePlus 13 Android 16 baseline

The current `aospa-op13/android_device_oneplus_sm8750-common` blob list is sourced from
**OnePlus 13 CPH2653 16.0.10.501(EX01)**. It is the closest public stock-derived baseline currently
found for the same device family/release.

Confirmed components:

#### Standard KeyMint / TEE path

```text
vendor/bin/hw/android.hardware.security.keymint-service-qti
vendor/etc/vintf/manifest/android.hardware.security.keymint-service-qti.xml
vendor/lib64/libqtikeymint.so
vendor/lib64/libqtikeymaster4.so
vendor/lib64/libkeymasterprovision.so
vendor/bin/KmInstallKeybox
vendor/lib64/libspcom.so
```

This is the primary backend TES strict `hardware` mode should wrap.

#### IFAA / fingerprint payment path

```text
vendor.oplus.hardware.biometrics.fingerprintpay@1.0-service
manifest_oplus_ifaa.xml
libifaa_factory.so
librpmbengclient.so
secure_ta/alipay.*
```

An open IFAAService implementation forwards `processCmd_v2(byte[])` directly to the vendor
`IFingerprintPay` HAL. Therefore IFAA is an OEM payment/TEE bridge, not merely a KeyMint parameter.

#### Widevine L1

The same OnePlus 13 baseline contains:
- `com.google.android.widevine.nonupdatable.apex`;
- `oplus_Widevine_licenses.pfm`, copied into persistent license storage at boot;
- `liboemcrypto.so`;
- `libtrustedapploader.so`.

Widevine L1 belongs to the DRM/OEMCrypto secure path. TES KeyMint code must not claim to implement
Widevine merely because a KeyMint key succeeds.

#### HDCP

The baseline contains:
- `wfdhdcphalservice`;
- `android.hardware.drm@1.1-service.wfdhdcp.rc`;
- `libwfdhdcpcp.so`;
- `libwfdhdcpservice_proprietary.so`.

HDCP is likewise a distinct WFD/DRM security service.

#### RPMB

Confirmed in the platform/vendor stack:
- QTI `librpmb.so`;
- OPlus IFAA side includes `librpmbengclient.so`;
- older OnePlus generations exposed `vendor.oneplus.hardware.rpmb@1.0-service`.

RPMB must be treated as secure-storage infrastructure used by several TAs/services, not as a normal
AndroidKeyStore key type.

### 5.2 OPlus FIDO/FIDO2 / cryptoeng

Across modern OPlus/OnePlus stock dumps the payment stack includes:

```text
vendor.oplus.hardware.cryptoeng.ICryptoeng/default
vendor.oplus.hardware.fido.fidoca.IFidoDaemon/default
vendor.oplus.hardware.fido.fido2ca.IFidoDaemon/default
fidotap secure TA
fidoctap secure TA
lib_cryptoeng_api.so
libqsee_keybox_ca.so
```

Several stock-derived repositories explicitly describe the FIDO daemons as cryptoeng runtime Binder
servers that load `fidotap` / `fidoctap` through QSEECom.

These components were **not confirmed in the current public OnePlus-13 AOSPA blob list**. That absence
is not proof that PJZ110 stock lacks them; they may be product/region-specific or omitted by the custom
ROM extraction. Treat OnePlus-13 FIDO support as **needs stock-device confirmation**, not false.

### 5.3 Soter

Tencent's design is:

```text
ATTK (factory / device)
  -> signs ASK
       -> signs AuthKey
            -> signs transaction after biometric authorization
```

Qualcomm devices expose a separate Soter service/TA. A recent OhMyKeymint-derived implementation has
OnePlus 13 transaction captures for the Qualcomm Soter AIDL and notes that OPlus engineering-mode
`verifyAttkKeyPair` reaches the path through cryptoeng.

This makes Soter a candidate for a TES **OEM backend bridge**, not an `IKeyMintDevice` extension.

---

## 6. Mapping the OPlus engineering Key page to real subsystems

The engineering UI is an observer, not the implementation target. Public tooling calling
`com.oplus.engineermode.security.SecurityInterface` confirms at least:

```text
isSoterKeySupport()
verifyAttkKeyPair()
getDeviceId()
isGoogleKeyImport()
genRkpInfo("default")
isSupportRkpWidevine()
genRkpInfo("widevine")
queryDrmInfo()
```

Use these methods to identify the real subsystem, not to fake their result.

| Engineering item | Real subsystem TES must make functional | Current confidence |
| --- | --- | --- |
| RPMB key | RPMB / QSEE secure-storage infrastructure; possibly OEM RPMB service/client | high for subsystem, transaction contract still TBD |
| SOTER key | Qualcomm/OPlus Soter service + TA, ATTK/ASK/AuthKey hierarchy | high |
| IFAA key | OPlus fingerprintpay HAL + alipay TA + RPMB support | high |
| Crypto key | OPlus cryptoeng/QSEE path where present; ordinary app crypto remains KeyMint | medium-high; PJZ110 exact cryptoeng inventory still to confirm |
| Widevine L1 key | Widevine DRM APEX + OEMCrypto + trusted TA/provisioning | high |
| HDCP key | WFD HDCP / DRM HAL and HDCP secure provisioning | high |
| Attestation / Google key | KeyMint + keybox and/or RKP hardware attest key | high |
| FIDO key | OPlus `fidoca` + `fidotap` TA where present | high platform-wide; PJZ110 exact presence TBD |
| PKI cert | **unresolved**; do not confuse with QTI network `CACertService` without evidence | low |
| PKI Group cert | **unresolved**; requires EngineerMode/SecurityInterface reverse mapping | low |
| FIDO2 key | OPlus `fido2ca` + `fidoctap` TA where present | high platform-wide; PJZ110 exact presence TBD |
| RKP default | Android RKPD + real IRemotelyProvisionedComponent / KeyMint security level | high |
| RKP widevine | OPlus/Widevine provisioning path, distinct from ordinary KeyMint RKP | medium-high |
| StrongBox key | independent real StrongBox IKeyMintDevice / secure processor when physically present | high definition; PJZ110 exact service topology must be runtime-confirmed |

---

## 7. New architecture implied by the research

TES should not grow into one giant `keymint_router.cpp`. Split the backend graph.

```text
                         +----------------------+
selected caller -------->| TES caller resolver  |
                         +----------+-----------+
                                    |
                  +-----------------+-----------------+
                  |                                   |
          Standard Android                    OEM secure sidecars
          security services
                  |                                   |
      +-----------+-----------+        +--------------+------------------+
      |                       |        |        |        |       |       |
   TEE KM                 StrongBox KM Soter   IFAA    FIDO   DRM    RPMB/PKI
      |                       |        bridge  bridge   bridge  bridge   bridge
 real QTI HAL             real SB HAL            vendor AIDL/HIDL/QSEE/TA
```

Suggested interfaces:

```text
BackendIdentity
  - kind
  - exact Binder/service instance
  - hardware info / version
  - availability epoch
  - capability set

KeyBackend
  - generate/import/wrapped-import
  - begin/update/finish
  - upgrade/delete/characteristics
  - attest/RKP
  - state/trust-service evidence

OemSecureBackend
  - service discovery
  - protocol/version probe
  - transaction bridge
  - persistent/secure-state ownership declaration
  - functional conformance test
```

OEM bridges must not be enabled merely because a service name exists. Each bridge needs at least one
real functional transaction proving that its secure backend is alive.

---

## 8. Immediate implementation consequences for PR #4

### P0 — keep current strict hardware invariants

Continue enforcing:
- real exact-level blob ownership;
- no software fallback;
- exact KeyCharacteristics security level;
- KeyDescription security-level agreement when present;
- genuine delegated ATTEST_KEY graph;
- real SharedSecret/SecureClock/HAT/state ownership;
- real StorageKey/RKP ownership.

### P1 — add versioned backend ownership/migration

Borrow the **concept** from AOSP km_compat:
- distinguish TES legacy software blob, genuine TEE, genuine StrongBox and any compatibility backend;
- implement an explicit migration path for aliases created before `hardware` mode;
- never interpret an old software marker as hardware after an update.

### P1 — make StrongBox an independent backend object

Replace remaining global/heuristic assumptions with a concrete StrongBox backend identity:
- exact service/Binder;
- own health epoch;
- own capability matrix;
- own operation limits;
- own RKP/SharedSecret evidence;
- no fallback to TEE under the name StrongBox.

### P2 — build the OEM sidecar framework before individual features

Do not mix Soter/IFAA/FIDO/DRM logic into `IKeyMintDevice`.
First add a small backend registry/discovery abstraction, then implement:
1. Soter;
2. IFAA/fingerprintpay;
3. FIDO/FIDO2;
4. RPMB-facing secure storage where safe/understood;
5. DRM/Widevine/HDCP only at their actual service layer;
6. PKI only after the real provider is identified.

### P2 — expand device conformance tests

For TEE and StrongBox independently:
- EC P-256 generate/sign/verify;
- RSA sign/verify;
- AES-GCM roundtrip;
- HMAC roundtrip;
- importKey;
- importWrappedKey where supported;
- auth-bound key after real biometric/HAT;
- StorageKey conversion;
- rollback/usage-limited behavior;
- ATTEST_KEY delegated graph;
- RKP-assigned attest key;
- keystore2 restart persistence;
- KeyDescription provenance.

A test result is evidence; it must not toggle a fake feature bit.

---

## 9. Open questions / next research pass

1. Obtain the exact PJZ110/ColorOS 16 VINTF/service inventory for:
   - `IKeyMintDevice/strongbox`;
   - `ISharedSecret` / `ISecureClock`;
   - OPlus cryptoeng;
   - fidoca/fido2ca;
   - Soter service instance.
2. Reverse-map EngineerMode's **PKI cert** and **PKI Group cert** checks. QTI `CACertService` is present
   on OnePlus 13, but there is currently no evidence that it is the provider behind those two rows.
3. Determine exact OnePlus-13 RPMB-engine protocol still used by fingerprintpay/engineering mode.
4. Determine whether `RKP widevine` uses an OEM remote provisioning component, cryptoeng, or a DRM
   provisioning API on current ColorOS.
5. Compare current TES keystore2 interception coverage to TrickyStore's alias/grant/metadata lifecycle
   and add only the missing semantics relevant to actual TES-owned keys.
6. Device-test PR #4 on PJZ110 before promoting `hardware` mode from opt-in.

---

## 10. Research rule for future work

Before implementing any item that an engineering UI labels as a "key":

1. identify the real service/HAL/TA that owns it;
2. identify where the private/secret material lives;
3. identify the persistent secure state (RPMB/eSE/TEE/etc.);
4. identify its actual functional transaction;
5. only then connect it to TES.

A green text label is never the acceptance criterion. A successful end-to-end operation through the
correct security domain is.


---

## 11. Research pass 2 — implementation details that materially change TES

### 11.1 AOSP KeyMint reference TA: backend contracts, not just APIs

Primary source:
- https://android.googlesource.com/platform/system/keymint/
- mirror used for code inspection:
  https://github.com/LineageOS/android_system_keymint

The reference TA makes the device-specific boundary explicit. A complete secure backend supplies,
among other things:

- `RetrieveKeyMaterial::root_kek()` — hardware-rooted material used to derive per-keyblob KEKs;
- `RetrieveKeyMaterial::kak()` — the key-agreement key used by SharedSecret;
- `hmac_key_agreed()` — optional installation of the per-boot device HMAC into hardware;
- `SecureDeletionSecretManager` — secure-deletion / rollback state;
- `StorageKeyWrapper` — storage-key ephemeral wrapping;
- `RetrieveRpcArtifacts` — RKP hardware-backed derivation, DICE artifacts and signing.

This gives TES a precise definition of "real backend integration": strict hardware mode must leave
these capabilities in the genuine security domain instead of reproducing them with ordinary Android
process memory/files.

The current reference TA also distinguishes operation capacity by security domain:

- TEE operation slots: 16;
- StrongBox operation slots: 4.

Therefore the old TES simulator-only StrongBox cap of 16 must not be treated as an AOSP-conformant
StrongBox limit. For a real backend TES should propagate the real HAL's pressure. For software
compatibility mode, use a level-specific table aligned with the chosen reference version rather than
one global number.

### 11.2 Ready SE / JavaCard StrongBox: what a real second KeyMint instance looks like

Primary sources:
- https://android.googlesource.com/platform/external/libese/+/refs/heads/main/ready_se/
- JavaCard KeyMint applet:
  https://android.googlesource.com/platform/external/libese/+/refs/heads/main/ready_se/google/keymint/

The Ready SE applet is useful precisely because it is not "TEE with a different enum":

- Android-side HAL transports commands to a secure-element applet;
- KeyMint state and private material live on the secure element;
- SharedSecret is implemented for the secure-element domain;
- transport/APDU availability is a first-class backend state;
- functionality can legitimately be narrower than TEE.

The public KM200 applet explicitly documents KeyMint 1.0 + SharedSecret support and also documents
features it does not implement, including limited-usage keys. That is a critical TES rule:
**unsupported StrongBox features remain unsupported**. Software completion of a missing feature cannot
then be represented as hardware-enforced StrongBox.

### 11.3 Keystore2 SharedSecret negotiation: TES must observe, not restart it

Primary source:
- https://android.googlesource.com/platform/system/security/+/refs/heads/main/keystore2/src/shared_secret_negotiation.rs
- interface overview:
  https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/security/README.md

Android performs an N-party per-boot shared-secret negotiation across the participating security
components. The resulting HMAC secret is what links Gatekeeper/biometric HATs with KeyMint domains.

TES consequence:

- strict TEE/StrongBox mode should use the already-negotiated real backend;
- do not call `computeSharedSecret()` again as a "setup" step from TES;
- read-only health evidence is acceptable;
- auth-bound keys must fail closed if their genuine backend is unavailable.

This confirms the current PR #4 design direction.

### 11.4 TrickyStoreOSS: mature Keystore2 lifecycle coverage, but software ownership

Source:
- https://github.com/beakthoven/TrickyStoreOSS

Its `SecurityLevelInterceptor` is particularly useful as a checklist because it handles more than
certificate generation:

- `generateKey`, `importKey`, `createOperation`;
- alias, UID, namespace and grant ownership;
- persistent metadata / patched responses;
- cleanup on delete/reset;
- designated attestation-key lookup;
- challenge-length validation;
- device-ID-attestation permission checks;
- version/transaction quirks;
- timing normalization for software-forged paths.

TES should independently reproduce only the lifecycle/scoping concepts that it is missing.
The software keypair maps, software usage counters and forged timing are **not** evidence of a real
TEE/StrongBox backend and must never cross into strict hardware mode.

A useful specific rule to adopt: key ownership is not synonymous with alias. Namespace and grants can
be the stable lookup identity, so TES migration/lifecycle code must preserve those relationships.

### 11.5 AOSP km_compat: the closest precedent for TES hybrid routing

Primary source:
- https://android.googlesource.com/platform/system/security/+/refs/heads/main/keystore2/src/km_compat/

Android itself uses a hybrid model when an older hardware Keymaster lacks a newer feature. The key
lesson is not "software can pretend to be hardware"; it is the opposite:

- blobs are explicitly tagged by the backend that created them;
- later operations return to that same backend;
- emulation decisions are feature-specific;
- real hardware identity remains real hardware identity;
- StorageKey / wrapped-key and other hardware-bound operations stay on the real backend.

This should become the model for TES compatibility mode:
**feature emulation may coexist with hardware, but backend ownership and enforcement level must remain
explicit.**

### 11.6 OhMyKeymint: state mirroring and recovery are more important than crypto imitation

Source:
- https://github.com/qwq233/OhMyKeymint

The strongest reusable ideas are around keystore2 state coordination:

- Authorization and Maintenance are mirrored, not treated as stateless request proxies;
- CE/LSKF state and super-key availability are explicit states;
- failed mirror events are marked dirty and replayed later;
- restart recovery has separate queues/lanes so one interface does not silently imply another is
  synchronized;
- device lock/unlock and password transitions are treated as persistent state-machine events.

TES consequence:
- add backend epochs + pending state replay for transitions that must reach the real backend;
- never return "state changed" success solely because the Binder endpoint was temporarily absent;
- if TES ever owns compatibility-mode CE state, model CE locked/unlocked explicitly rather than using
  a single boolean.

License boundary remains: learn concepts/protocol behavior, implement independently.

### 11.7 Tencent Soter: a real OEM hierarchy, not a KeyMint capability bit

Primary sources:
- https://github.com/Tencent/soter
- https://github.com/Tencent/soter/wiki/%E5%8E%9F%E7%90%86

The public architecture is:

```text
factory/device ATTK
        |
        +--> signs ASK (per app)
                 |
                 +--> signs AuthKey (per business/auth scene)
                           |
                           +--> biometric-authorized signatures
```

The private keys are designed to remain inside the TEE (or protected by TEE-rooted secure storage),
and the signatures are verified by the relying backend.

Therefore a future TES Soter integration must either:
- bridge the genuine vendor Soter service/TA and preserve this hierarchy; or
- be explicitly labelled a compatibility emulator.

It must not map Soter to a normal KeyMint EC/RSA key and then call the result "real Soter".

### 11.8 StrongBox conformance implications for TES

A backend can only be called strict StrongBox when all of the following are true:

1. the exact `IKeyMintDevice/strongbox` (or legacy equivalent) is resolved;
2. generated key material is owned by that backend;
3. a real begin/update/finish round-trip succeeds;
4. `KeyCharacteristics` reports StrongBox where that backend enforces the authorization;
5. when a KeyDescription exists, both attestation and KeyMint security levels agree with StrongBox;
6. auth-bound operation succeeds with the real system HAT path;
7. keystore2 restart does not reset hardware-owned state;
8. unsupported StrongBox features remain unsupported rather than being filled by the software TA;
9. RKP/SharedSecret/SecureClock relationships match the real backend when those services are
   advertised;
10. delegated ATTEST_KEY signatures remain cryptographically valid under the actual parent key.

This is a stricter and more useful acceptance definition than any engineering-mode "success" row.

---

## 12. Adoption matrix after the broad prior-art survey

| Prior art / subsystem | Adopt now | Adapt later | Never classify as strict hardware |
| --- | --- | --- | --- |
| AOSP KeyMint TA contracts | backend boundaries, state ownership, conformance semantics | software compatibility backend | host/process secrets |
| AOSP keystore2 km_compat | backend-origin tracking, hybrid routing, migration | versioned TES compatibility envelope | relabelling emulated features as hardware |
| Ready SE / JavaCard KeyMint | separate StrongBox backend identity, transport state, SharedSecret shape | secure-element adapter if target exposes one | process-local StrongBox substitute |
| TrickyStoreOSS | caller scoping, namespace/grant lifecycle, metadata cleanup | missing keystore2 surface coverage | its software key ownership model |
| KeystoreInjection / FrameworkPatch family | targeted interception and chain-consistency test ideas | framework-visible conformance tests | provider-only keys as hardware keys |
| OhMyKeymint | mirror/recovery state-machine ideas, VINTF/service hardening | CE compatibility state | file-backed SDD as rollback-resistant hardware |
| Tencent Soter | service/TEE hierarchy and acceptance tests | real OEM Soter adapter | ASK/AuthKey response forgery as real Soter |
| OPlus IFAA/FIDO/cryptoeng | service discovery and real-TA routing | exact PJZ110 protocol adapters | UI status hooks as capability proof |

### Implementation order implied by this matrix

1. **Backend identity + epoch/reconnect state** for TEE and StrongBox.
2. **Backend-origin/migration metadata** for TES compatibility blobs; raw genuine hardware blobs remain
   opaque.
3. **Pending state replay** for boot/lifecycle transitions.
4. **Per-backend operation manager**; do not impose simulator limits on forwarded hardware ops.
5. **Device conformance harness** derived from AOSP VTS, with different expected capability sets for
   TEE vs StrongBox.
6. Only then add **OEM secure sidecars** (Soter → IFAA → FIDO/FIDO2 → cryptoeng/RPMB), each backed by
   a real functional transaction.
