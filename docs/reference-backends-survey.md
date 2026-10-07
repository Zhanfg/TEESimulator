# TES backend reference survey

> Working definition: TES is not a UI/status faker. For targeted callers it must expose a coherent,
> usable TEE/StrongBox security backend. When genuine hardware exists, business private keys and
> security state remain in that hardware domain; TES provides routing, compatibility and attestation
> reconstruction around it. Software paths must never be presented as physical StrongBox.

## 1. Source families

### AOSP Keystore2 / system KeyMint

Sources:
- https://github.com/LineageOS/android_system_security
- https://github.com/msft-mirror-aosp/platform.system.keymint

Key lessons:

1. A security level is a backend identity, not a display label.
   Keystore2 maps each requested `SecurityLevel` to a concrete KeyMint device UUID and stores that UUID
   alongside the key blob. Later upgrade, use, deletion and GC return to the same KeyMint instance.
2. KeyMint extension points which define a real backend include:
   - root key material / keyblob encryption
   - `SecureDeletionSecretManager`
   - `StorageKeyWrapper`
   - `RetrieveRpcArtifacts`
   - bootloader state
   - attestation IDs / signing information
   - trusted user presence
3. In-memory secure deletion is explicitly example-only. A real rollback-resistant implementation
   needs persistence inaccessible to normal Android.
4. Keystore2 operation lifetime is stateful: every operation has a single terminal outcome; drop and
   pruning abort the underlying KeyMint operation; operation-slot pressure is handled by pruning based
   on UID sibling count + age/LRU, not a global blind counter.
5. Genuine SecureClock/RKP services are discovered independently per service/security level; absence is
   reported as `HARDWARE_TYPE_UNAVAILABLE`, not silently emulated.

TES adoption:
- Introduce an explicit backend-domain identity (TEE, StrongBox and later vendor secure domains) and
  bind every persistent key to it.
- Do not infer backend ownership from certificate text or service names after key creation.
- Mirror Keystore2's operation terminal-state discipline and per-owner pruning rather than relying only
  on a global StrongBox slot counter.

### Trusty KeyMint

Source:
- https://github.com/bluestacks/trusty-user-app-keymint-a16 (AOSP mirror, branch `aosp16-sync`)

Key lessons:

1. `TrustySecureDeletionSecretManager` stores factory-reset and per-key deletion secrets through
   Trusty secure storage transactions, not an Android data file.
2. Storage keys use a dedicated `hwwsk` Trusty service:
   - storage-key material is opaque;
   - AES storage keys are generated/imported by the secure service;
   - `StorageKeyWrapper.ephemeral_wrap` exports only the ephemeral wrapped representation;
   - opaque storage keys are rejected for normal AES operations.
3. Rollback resistance is a secure-service capability. The storage-key implementation may retry
   without rollback resistance when the lower service explicitly returns NotSupported, rather than
   pretending the stronger property exists.

TES adoption:
- Current strict-hardware routing is correct for devices with genuine KeyMint: keep StorageKey,
  rollback-resistant state and conversion entirely in the real HAL.
- If TES later gains a self-contained TEE backend, its SDD and StorageKey services must be anchored
  outside the Android process (Trusty/QSEE/secure element/RPMB-backed service). A file-backed or
  in-process implementation must not qualify as strict hardware.

### JavaCard / eSE StrongBox

Source:
- https://github.com/ThalesGroup/javacard-keymint-hal (branch `5.0`)
- related NXP mirrors: `platform.hardware.nxp.keymint`,
  `android_vendor_nxp_opensource_keymaster`

Key lessons:

1. The Android C++ HAL is a bridge. `generateKey`, `importKey`, `begin`, wrapped-key import and
   lifecycle commands are CBOR/APDU requests sent to the secure-element applet. Key blobs,
   characteristics and certificate chains come back from the SE.
2. `getHardwareInfo` obtains the applet's own security level/version/identity; StrongBox is not
   created by the proxy merely reporting `STRONGBOX`.
3. `ISharedSecret` is implemented by the secure element itself. The implementation initializes the
   card, retries transient startup failures and sends both get-parameters and compute-secret commands
   into the SE.
4. Important lifecycle signals are not discarded if the SE is temporarily unavailable.
   `deleteAllKeys`, `earlyBootEnded` and additional attestation information can remain pending and
   are replayed when the SE becomes usable.
5. RKP is a separate hardware service. `generateEcdsaP256KeyPair` returns a MACed public key plus an
   opaque private-key handle from the SE; CSR v2 signing, DICE chain and UDS chain are also produced
   through the secure element.
6. APDU size/chunking and transport errors are first-class backend concerns.

TES adoption:
- Add pending-event replay to real backend adapters instead of returning success and losing state on a
  transient binder/secure-service outage.
- Keep StrongBox RKP identity and KeyMint identity as two linked but separate services.
- Treat transport health separately from capability health.
- Future non-native StrongBox adapters need a genuine isolated executor/SE transport. A process-local
  TA cannot graduate to physical StrongBox merely by implementing the same API.

### Cuttlefish secure_env

Source:
- https://github.com/google/android-cuttlefish

Key lessons:
- Good reference for assembling a complete Rust KeyMint TA and RKP artifacts.
- Its host-file secure-deletion manager is intentionally only protected from Android, not from the
  host. This is useful for functional simulation but not equivalent to physical TEE/StrongBox.

TES adoption:
- Reference for test/fallback backend only, not strict-hardware trust claims.

## 2. Keystore / attestation interception projects

### Zygisk-KeystoreInjection

Source:
- https://github.com/aviraxp/Zygisk-KeystoreInjection

Architecture:
- inject only selected application processes;
- replace the `AndroidKeyStore` Java Security provider;
- delegate most normal KeyStore SPI methods to the original provider;
- replace key generation/certificate retrieval with a custom software provider and keybox chain.

Useful patterns for TES:
- precise caller scoping;
- preserve the original provider for untouched operations;
- isolate compatibility behavior from non-target apps.

Not suitable as a TES hardware backend:
- generated private keys are software/app-process keys;
- changing provider/certificate surface does not create TEE or StrongBox ownership.

### TrickyStoreOSS

Source:
- https://github.com/beakthoven/TrickyStoreOSS

Architecture / useful details:
- intercepts Keystore2 security-level binder operations;
- forwards symmetric keys and many ordinary requests to real hardware;
- modifies only the operations where attestation replacement is needed;
- keeps returned authorizations and KeyDescription patch levels consistent;
- preserves the hardware leaf public key while rebuilding the certificate;
- accounts for older Keymaster quirks such as swapped software/TEE authorization lists;
- tracks aliases, UID/domain/namespace, grants and deletion;
- persists software keys asynchronously, outside Binder threads.

TES adoption:
- copy concepts, not source: targeted binder scoping, metadata consistency, old-Keymaster tolerance and
  off-Binder persistence/work queues.
- strict hardware mode must not adopt its software private-key persistence model.

### FrameworkPatch / BootloaderSpoofer family

Representative mirrors:
- https://github.com/ExtremeXT/FrameworkPatch
- https://github.com/takattowo/BootloaderSpoofer
- detector/reference: https://github.com/LingQingBigKing/TrustAttestor

Key lesson:
- framework-level certificate surgery is easy to make internally inconsistent. Public detectors have
  specifically caught implementations whose returned certificate contains the wrong subject public
  key. TES must always verify:
  - certificate SPKI == generated/imported hardware key public half;
  - child certificate signature verifies under the delegated parent when one exists;
  - Binder-returned chain and framework-visible chain agree.

TES adoption:
- turn these into conformance assertions, not only implementation guidance.

## 3. OhMyKeymint

Source:
- https://github.com/qwq233/OhMyKeymint

Useful patterns:
- broad keystore2/Binder interception;
- VINTF-aware service resolution;
- restart/race hardening;
- authorization/maintenance state mirroring;
- RKP/DICE implementation in the reference TA;
- persisted secure-deletion manager with corruption validation/reinitialization.

Boundary:
- public file-backed SDD is functional persistence, not a physical secure-storage root;
- public source has historically left `StorageKeyWrapper` disabled in the software TA.

TES adoption:
- independently reproduce lifecycle/state-machine concepts where useful;
- do not copy AGPL source;
- do not classify Android-file-backed SDD as strict hardware.

## 4. OPlus / OnePlus vendor security domains

### IFAA / fingerprint payment

Sources:
- `OnePlus-12-Development/android_hardware_oplus/IFAAService`
- OnePlus SM8750 vendor manifests in
  https://github.com/TheMuppets/proprietary_vendor_oneplus_sm8750-common

Observed chain:
`IfaaManagerService.processCmd(byte[])`
→ `vendor.oplus.hardware.biometrics.fingerprintpay.IFingerprintPay/default`
→ `ifaa_invoke_command(byte[])`
→ vendor/secure-world implementation.

The service has Binder death handling and reconnects lazily. The vendor rc also sets
`vendor.oplus.ifaa.need_init` at boot.

TES consequence:
- IFAA is not just a KeyMint tag. A complete OPlus implementation needs an adapter for the
  fingerprintpay domain and its secure-world command path.
- Reuse the lazy binder death/reconnect pattern.

### FIDO / FIDO2

Public service evidence:
- `vendor.oplus.hardware.fido.fidoca.IFidoDaemon/default`
- `vendor.oplus.hardware.fido.fido2ca.IFidoDaemon/default`
- OPlus/OnePlus vendor packages include `fidotap` and `fidoctap` QSEE secure-TA images.

Recent public vendor manifests describe the two Binder daemons as loaders/servers for those QSEE TAs.

TES consequence:
- FIDO and FIDO2 are separate vendor secure domains, not aliases for AndroidKeyStore EC keys.
- KeyMint hardware ownership still matters for any AndroidKeyStore material they consume, but full
  compatibility requires forwarding/adapting their Binder/TA command protocol.
- Do not invent the unpublished IFidoDaemon transaction schema. Obtain it from device AIDL metadata,
  generated NDK libraries, or controlled binder tracing before implementing an adapter.

### OPlus cryptoeng / Keybox / RPMB

Public evidence:
- AIDL service `vendor.oplus.hardware.cryptoeng.ICryptoeng/default`;
- reconstructed/public AIDL shows a byte-array command interface
  `cryptoeng_invoke_command(byte[])`, but this must be verified against the target device's
  generated V1 NDK interface before implementation;
- service is backed by `cryptoeng.*` TrustZone TA images on Qualcomm builds;
- OPlus vendor trees contain `librpmbengclient.so`, `librpmb.so`, `KmInstallKeybox`, and keybox
  CA libraries;
- public third-party software stubs explicitly warn that replacing this with Android-file-backed AES
  storage restores UI functionality but is not secure.

TES consequence:
- this is exactly the distinction TES must preserve: protocol compatibility alone is not enough.
- Build a `VendorSecureBackend` abstraction whose strict implementation forwards to the genuine
  cryptoeng/QSEE/RPMB path and treats a software stub as a separate fallback class.
- For OnePlus 13-class Qualcomm devices, investigate the real `cryptoeng_invoke_command` command
  IDs and `librpmbengclient` relationship from device binaries before changing runtime behavior.

### Soter

Public Qualcomm/OPlus/OnePlus device trees show:
- `vendor.qti.hardware.soter@1.0-service`
- `SoterService.apk`
- vendor Soter implementation libraries / provisioning tools on multiple generations.

TES consequence:
- Soter has its own HAL/TA lineage; it should become another vendor secure backend adapter, not a
  synthetic KeyMint capability bit.

## 5. Architecture changes this survey implies for TES

### 5.1 Backend-domain identity

Introduce a stable backend identity, conceptually:

```
BackendDomain {
  kind: Tee | StrongBox | OplusCryptoEng | OplusFido | OplusFido2 | OplusIfaa | QtiSoter,
  service_instance,
  hardware_identity,
  generation,
}
```

Every persistent TES-managed reference must remember its backend domain. Do not rediscover ownership
from a certificate or string heuristic on each operation.

### 5.2 Separate control plane from secret plane

Control plane may live in TES/keystore2:
- caller/profile routing
- binder death/reconnect
- VINTF discovery
- attestation certificate transformation
- policy
- diagnostics

Secret plane must remain in the selected secure backend:
- private/secret key material
- root KEK
- SharedSecret-derived HAT verification state
- rollback / secure-deletion secrets
- StorageKey wrapping root
- RKP/DICE private material
- RPMB-backed state where required.

### 5.3 Pending-event replay

Per backend maintain a small monotonic event/state queue for signals that must survive a temporary
service outage:
- earlyBootEnded
- deleteAllKeys
- additional attestation/module info
- device lock state where applicable
- backend generation/reconnect epoch

Never return successful state transition merely because the secure backend was temporarily absent.

### 5.4 Operation manager

Replace/augment the simple simulated StrongBox active counter with:
- per-backend operation registry;
- terminal outcome exactly once;
- abort-on-drop;
- backend death invalidation;
- per-UID fairness/LRU pruning when the real backend returns `TOO_MANY_OPERATIONS`;
- no counting of forwarded operations against a software fallback table.

### 5.5 Conformance gates

A backend may be called strict TEE/StrongBox only after:
- genuine service identity resolved;
- generate + begin/update/finish works;
- key characteristics report expected level;
- attestation KeyDescription, when present, reports the same level on both axes;
- key public half matches certificate SPKI;
- reboot/reconnect preserves persistent key usability;
- auth-bound operation accepts genuine system HAT and rejects stale/invalid token;
- StorageKey round-trip works when advertised;
- rollback/usage counters survive keystore2 process restart;
- RKP component belongs to the same security domain when advertised.

Vendor-domain gates must additionally prove the actual TA/HAL transaction, not only Binder service
presence.

## 6. Priority implementation order

1. Finish strict TEE/StrongBox backend-domain ownership and operation lifecycle.
2. Add pending-event replay and backend death epochs.
3. Add hardware-domain conformance tests: persistence/reboot, auth-bound, StorageKey, rollback/usage,
   delegated ATTEST_KEY and RKP.
4. Add `VendorSecureBackend` discovery and passive protocol inventory for OPlus:
   cryptoeng → RPMB/keybox, fingerprintpay/IFAA, FIDO, FIDO2, then Soter.
5. Only after exact target-device interfaces are known, implement vendor adapters that forward real
   secure-world commands.
6. Keep software emulation as an explicitly separate compatibility backend, never as strict hardware.

## 7. Explicit non-goals

- No UI-only “success” flags.
- No `SecurityLevel::STRONGBOX` label on a process-local key as proof of StrongBox.
- No Android-file secret store classified as secure deletion/RPMB.
- No fabricated FIDO/IFAA/Soter response counted as a real vendor TEE path.
- No certificate rewrite that breaks SPKI or delegated signature relationships.


## 8. VTS-derived conformance boundaries

Primary source:
- AOSP `hardware/interfaces/security/keymint/aidl/vts/functional`

These tests should become the model for TES device-side backend verification instead of inventing a
TES-only definition of "working".

### Operation correctness

A real backend is expected to survive full create/use/delete semantics, not only key creation.
Relevant VTS coverage includes:
- RSA sign/verify;
- EC sign/verify;
- AES encrypt/decrypt and AEAD behavior;
- HMAC known-answer tests;
- import parameter mismatch handling;
- malformed key-blob handling;
- begin/update/updateAad/finish/abort lifecycle and input limits.

StrongBox deliberately has a narrower primitive/parameter set in multiple tests. Therefore TES must
not infer that a missing optional/non-StrongBox algorithm means the StrongBox backend is fake.

### StrongBox-specific expectations / exceptions

Current AOSP tests demonstrate several important distinctions:
- P-256 EC and RSA-2048 are core StrongBox asymmetric profiles exercised by VTS;
- AES-128/AES-256 and HMAC are exercised within StrongBox-valid parameter ranges;
- several HMAC digests exercised for TEE are skipped for StrongBox, while SHA-256 remains exercised;
- P-521 EC import is explicitly skipped for StrongBox;
- device-unique attestation is StrongBox-specific but optional; `CANNOT_ATTEST_IDS` is an allowed
  unsupported result;
- some usage-limit tests such as `MAX_USES_PER_BOOT` are not applicable to StrongBox in current VTS.

TES consequence:
- conformance needs a per-level expected capability table, not one universal algorithm list.
- unsupported optional StrongBox features must remain unsupported rather than being "filled in" by a
  software path and then represented as hardware.

### Rollback resistance / deletion

AOSP VTS accepts either:
- explicit `ROLLBACK_RESISTANCE_UNAVAILABLE`, or
- a genuine rollback-resistant key whose authorization is hardware-enforced.

If implemented, deleting the key must make the retained old blob unusable
(`INVALID_KEY_BLOB`). `deleteAllKeys` has similarly destructive semantics.

TES consequence:
- strict mode may pass through "unavailable"; it must never add a rollback-resistance authorization
  unless the selected backend can enforce post-deletion invalidation across Android process/reboot
  boundaries.

### Operation pressure / pruning

Keystore2 reacts to backend `TOO_MANY_OPERATIONS` by pruning existing operations according to
owner/sibling count and age, with LRU used as a tie breaker. It also enforces one terminal outcome and
aborts unfinished operations on drop.

TES consequence:
- the present fixed StrongBox active-operation counter is at most a simulator compatibility rule.
- real-backend mode should propagate backend pressure and integrate a Keystore2-like owner-aware
  operation registry rather than imposing a second arbitrary hardware limit.

### Attestation proof

TES strict mode should add local equivalents of VTS assertions for every attested key:
1. generated/imported key can actually perform its advertised operation;
2. certificate SPKI corresponds to the key;
3. KeyCharacteristics security level is the selected backend level;
4. KeyDescription security levels agree when the extension exists;
5. delegated child certificate verifies under the actual parent ATTEST_KEY certificate;
6. deleting/upgrading the key does not silently move ownership to another backend.

This is the acceptance boundary for calling the backend TEE/StrongBox-capable.


## 9. Back-level Keymaster compatibility: a useful hybrid-routing precedent

Source:
- AOSP/LineageOS `keystore2/src/km_compat.rs` and `keystore2/src/km_compat/*`

This is one of the closest architectural precedents for TES because Android itself sometimes wraps an
older real hardware Keymaster with a current software KeyMint implementation.

Important behavior:

1. Software-emulated and hardware-owned blobs are explicitly distinguishable.
   The compat layer prefixes blobs so later `begin`, `deleteKey`, `upgradeKey` and
   `getKeyCharacteristics` return to the backend that actually created the key.
2. Emulation is feature-specific, not level-wide. For example a back-level TEE may remain the backend
   for normal keys while only a newer unsupported feature is routed to software.
3. `getHardwareInfo` still comes from the real device. The wrapper does not redefine the real
   hardware identity merely because it can emulate an API feature.
4. State transitions such as `deviceLocked` and `earlyBootEnded` may be propagated to both
   implementations so either kind of previously-created key receives the transition.
5. Hardware-bound operations are explicitly excluded from software emulation:
   `importWrappedKey` always goes to the real device, and StorageKey conversion is always real.
6. Legacy Keymaster characteristics are normalized into separate KeyMint-enforced and
   Keystore-enforced sets. New tags that Keystore itself can enforce are not falsely claimed as
   legacy hardware-enforced.
7. The C++ Keymaster wrapper has explicit operation-slot management and distinguishes real/software
   blobs for every subsequent operation.

TES adoption:
- promote the current TES marker idea into a versioned backend-origin envelope for compatibility
  blobs; strict hardware blobs remain untouched/opaque.
- decide compatibility fallback per feature/request, never by changing the claimed security level.
- record which authorization layer actually enforces a tag; do not move Keystore-enforced policy into
  the TEE/StrongBox authorization list just to make output look stronger.
- keep wrapped keys, StorageKey, HAT-dependent state, rollback state and other hardware-bound
  primitives out of the compatibility backend.

## 10. Useful anti-pattern references

These projects are useful for locating protocol surfaces, but they deliberately do not provide a
genuine secure backend.

### OPlus cryptoeng software stubs

Representative:
- https://github.com/cyberphantom52/oplus_cryptoeng_stub
- other ColorOS port projects that recreate `vendor.oplus.hardware.cryptoeng.ICryptoeng/default`

Useful information:
- confirms the AIDL service/instance and the single byte-array command surface used by current
  `ICryptoeng` reconstructions;
- helps enumerate callers and application behavior when the stock service is missing.

Hard boundary:
- public software stubs store state in Android-accessible files and explicitly warn that they do not
  reproduce the stock TrustZone security model.
- therefore they are protocol references only.

### D-Soter / Soter response forgers

Representative:
- https://github.com/ajfkdk/D-soter

Useful information:
- identifies the `com.tencent.soter.soterserver.ISoterService` transaction surface and shows a
  practical in-process Binder interception point.

Hard boundary:
- it intentionally forges ASK/AuthKey/session/signature/device responses and bypasses the vendor Soter
  HAL/TEE path.
- TES may learn service discovery/transaction scoping from it, but a strict Soter backend must reach
  the actual Qualcomm/OEM Soter TA and keep ATTK/ASK/AuthKey private material there.

This distinction is mandatory throughout TES documentation and UI:
`protocol-compatible` != `secure-backend` != `physical StrongBox`.
