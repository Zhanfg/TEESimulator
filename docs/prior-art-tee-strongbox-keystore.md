# TEE / StrongBox / Keystore prior-art survey

> Scope: implementation references for TEESimulator (TES) strict hardware backends.
>
> Core rule: TES is not a status spoofer. When hardware exists, business private keys, opaque key
> blobs and hardware-enforced state must remain in the genuine TEE / StrongBox security domain.
> TES may route calls and reshape attestation/certificate surfaces, but must not turn a software key
> into "hardware" by changing labels.

## Executive architecture conclusion

The surveyed implementations fall into four fundamentally different classes:

1. **Real secure-world KeyMint backends** — AOSP Trusty KeyMint and NXP JavaCard StrongBox.
   These are the primary architectural references for TES hardware mode.
2. **Compatibility bridges** — AOSP keystore2 `km_compat`.
   This is the primary reference for lifecycle adaptation, operation-slot ownership and legacy HAL
   translation without pretending one security level is another.
3. **Keystore/attestation interception modules** — TrickyStore / TrickyStoreOSS /
   Zygisk-KeystoreInjection.
   These are useful for Binder/provider compatibility, caller scoping and certificate rewriting, but
   their generated keys are software keys and must not define TES hardware semantics.
4. **OEM secure-service stacks** — Qualcomm Keymaster/QSEE, OPlus IFAA/FIDO/FIDO2, Tencent Soter.
   These prove that many items shown on OEM "Key Status" pages are independent secure applications /
   vendor services, not aliases for generic Android KeyMint.

For OnePlus 13 / SM8750 specifically, the practical hardware model is:

- **TEE**: Qualcomm KeyMint (`android.hardware.security.keymint-service-qti`,
  `libqtikeymint.so`, QSEE/secure storage).
- **StrongBox**: NXP JavaCard StrongBox
  (`android.hardware.security.keymint3-service.strongbox.nxp`).
- **IFAA / fingerprint pay**: OPlus fingerprintpay service + `libifaa_factory.so` +
  `librpmbengclient.so` + `alipay` secure TA firmware.
- **FIDO / FIDO2**: dedicated OPlus FIDO CA services which load their own secure TAs.
- **Widevine**: dedicated DRM / provisioning domain, not KeyMint.

That means TES should be designed as multiple real backend adapters plus overlays, not one software TA
whose `SecurityLevel` field is changed.

---

## 1. AOSP KeyMint Rust reference implementation

Repository:
- https://android.googlesource.com/platform/system/keymint/

Important surfaces:
- `IKeyMintDevice`
- `IRemotelyProvisionedComponent`
- `ISharedSecret`
- `ISecureClock`
- CBOR wire protocol between userspace HAL and secure-world TA

### What TES should copy conceptually

- Keep HAL-facing IPC and secure-world implementation separated.
- Treat KeyMint, SharedSecret, SecureClock and RKP as a *security-domain bundle*, not unrelated APIs.
- Key blobs are opaque domain-owned artifacts.
- Authorization enforcement belongs beside the key material, not in a metadata-only facade.
- RKP private keys are generated and retained inside the secure component; only public/certificate
  material leaves it.

### What TES must not infer

The reference TA can run in different environments; merely using its code does not make a process a
TEE or StrongBox. Hardware mode must use the platform's real backend.

---

## 2. AOSP Trusty KeyMint — reference for a genuine TEE backend

Repository:
- https://android.googlesource.com/trusty/app/keymint/

Android 17 components include:
- `keys.rs` / hardware key material abstraction
- `key_wrapper.rs` / `TrustyStorageKeyWrapper`
- `secure_deletion_secret_manager.rs`
- `secure_storage_manager.rs`
- `monotonic_clock.rs`
- `rpc.rs`
- attestation-key / keybox secure storage
- Trusty IPC channel

Trusty secure storage itself provides encrypted, tamper-proof storage and variants with rollback
detection.

### Secure deletion / rollback resistance

`TrustySecureDeletionSecretManager` stores per-key deletion secrets in Trusty secure storage. Those
secrets are incorporated into encrypted keyblob protection. Deleting the secure secret makes the old
blob cryptographically unusable.

**TES lesson:** rollback resistance is not a boolean tag. If TES ever implements a non-passthrough
secure backend, it requires durable secure-world state with anti-rollback semantics. In strict
hardware mode, leave this to QTI TEE / NXP StrongBox.

### StorageKey

`TrustyStorageKeyWrapper` is a dedicated implementation of KeyMint's StorageKey wrapping contract.

**TES lesson:** `STORAGE_KEY` and `convertStorageKeyToEphemeral` must remain a single backend
lifecycle. The current TES choice to keep StorageKey on the exact real HAL is correct.

### SharedSecret / HAT

Trusty registers KeyMint together with SharedSecret and SecureClock services. The HAT HMAC secret is
part of the real boot-time security-domain negotiation.

**TES lesson:** strict hardware TES must not independently rerun a partial SharedSecret negotiation.
Forward auth-bound operations to the real domain and preserve its negotiated state.

---

## 3. NXP JavaCard KeyMint — reference for a genuine StrongBox backend

Repository:
- https://android.googlesource.com/platform/hardware/nxp/keymint/

Key Android 17 / KM300 pieces:
- `JavacardKeyMintDevice.cpp`
- `JavacardKeyMintOperation.cpp`
- `JavacardSecureElement.cpp`
- `JavacardSharedSecret.cpp`
- `JavacardRemotelyProvisionedComponentDevice.cpp`
- dedicated StrongBox service/VINTF files

### Architecture

The Android Binder service is only a frontend. KeyMint commands are CBOR encoded and transported to
the secure element / JavaCard applet. `generateKey`, `importKey`, `begin`, wrapped-key import,
SharedSecret and RKP all cross that transport.

This is the most important StrongBox reference for TES because it demonstrates the correct invariant:

> A StrongBox backend is a distinct device/transport/state domain, not a TEE backend with
> `SecurityLevel.STRONGBOX` substituted.

### Operation lifecycle

NXP tracks live operations and transport timeout state, including fixes specifically around operation
count/lifetime.

**TES lesson:** forwarded StrongBox operations should remain NXP operations. TES may wrap Binder
objects for logging/compatibility, but must not recreate operation state in the software TA.

### SharedSecret

NXP implements `ISharedSecret` by sending the actual negotiation into the secure element.

**TES lesson:** if TES is wrapping a real NXP StrongBox, its SharedSecret service is authoritative.

### RKP

NXP supplies its own remotely provisioned component implementation, again backed by the secure
element.

**TES lesson:** TEE RKP and StrongBox RKP are separate backend identities. TES's per-level RKP routing
and inline certificate-only overlay should preserve this separation.

---

## 4. AOSP keystore2 km_compat — reference for safe compatibility wrapping

Repository:
- https://android.googlesource.com/platform/system/security/+/refs/heads/main/keystore2/src/km_compat/

Key pieces:
- `KeyMintDevice`
- `SharedSecret`
- `SecureClock`
- `OperationSlot`
- `OperationSlotManager`

`km_compat` adapts older Keymaster implementations into current KeyMint-facing interfaces while
retaining the actual backing device.

### Operation-slot pattern

`OperationSlot` owns slot release through RAII and explicitly guards against freeing the same slot
twice.

**TES lesson:** keep this model for any local bookkeeping around forwarded StrongBox operations.
Finish/abort/destructor/error paths must converge on exactly-once release.

### Security-level handling

The compatibility service caches devices/SharedSecret by requested security level and does not invent
a missing backend.

**TES lesson:** strict hardware mode should return unavailable when a real level cannot be resolved,
rather than replacing it with the TES TA.

---

## 5. OhMyKeymint — reference for full keystore2 state emulation, not physical StrongBox

Repository:
- https://github.com/qwq233/OhMyKeymint

Useful subsystems:
- full KeyMint TA
- Binder interception/rewrite
- `IKeystoreAuthorization`
- `IKeystoreMaintenance`
- credential-encrypted / unlocked-device super-key state
- secure deletion manager
- SharedSecret implementation
- RKP logic
- extensive compatibility handling

### Strong points worth adapting independently

- CE state is modeled explicitly (`CeLocked`, credential-encrypted super keys); it is not inferred
  from a superficial Android property.
- auth-bound APP keys do not silently fall back to unbound storage.
- maintenance/unlock/lock events are kept coherent with keystore state.
- host secure-deletion manager demonstrates how KeyMint reference semantics can be made persistent.
- Binder interception has strong transaction-layout/version compatibility work.

### Important limitation for TES hardware mode

Its host implementation is still software-hosted. Public source has `sk_wrapper: None`, so
StorageKey is not implemented by that software backend. A software-held SharedSecret/HMAC key also
does not make that process the device's physical TEE.

**TES use:** borrow state-machine and compatibility ideas, not its security-level claim.

License note: AGPL-3.0. Reimplement concepts independently; do not copy source into TES.

---

## 6. TrickyStore / TrickyStoreOSS — excellent interception reference, software-generation reference only

Repositories inspected:
- https://github.com/cytochromxxx/TrickyStore
- https://github.com/beakthoven/TrickyStoreOSS

### Older TrickyStore

It injects into keystore2, intercepts:
- `IKeystoreService.getKeyEntry`
- `IKeystoreSecurityLevel.generateKey`

It can replace certificate chains and synthesize `KeyMetadata` / `Authorization` with a requested
security-level value.

This is useful for:
- Binder injection placement
- caller/UID filtering
- certificate-chain post-processing
- compatibility with framework Keystore APIs

It is **not** proof of real TEE/StrongBox ownership.

### Newer TrickyStoreOSS

The newer OSS implementation is much deeper:
- intercepts `generateKey`, `createOperation`, `importKey`
- implements software operation Binder objects
- software RSA/EC/AES/HMAC/ECDH operations
- operation authorization checks
- usage-count handling
- key grant/namespace tracking
- persistent generated keys

Its persistence layer writes PKCS#8 private keys and raw secret-key bytes under
`/data/adb/tricky_store/keys`.

That fact is decisive: generated-mode keys are durable and functional, but they are still ordinary
software-held key material, not opaque TEE/StrongBox blobs.

### TES lesson

Borrow:
- comprehensive Binder coverage
- error-code compatibility
- alias / grant / namespace tracking
- operation parameter validation
- leaf-hack mechanics
- app/UID scoping

Do not borrow as hardware semantics:
- software operation engine
- plaintext/normal-filesystem private-key persistence
- synthetic `keySecurityLevel`

---

## 7. Zygisk-KeystoreInjection — provider-level compatibility reference

Repository:
- https://github.com/aviraxp/Zygisk-KeystoreInjection

It replaces the Java `AndroidKeyStore` provider with a custom provider, delegates many calls to the
original provider, and generates forged RSA/EC keypairs/attestation certificates in the app process
using BouncyCastle.

### TES lesson

Useful for:
- Java-provider compatibility edge cases
- certificate construction / API behavior

Not useful for:
- real KeyMint keyBlob
- HAT/SharedSecret
- SecureClock
- RPMB
- rollback resistance
- StrongBox transport

This is an explicit example of what TES hardware mode must *not* become.

---

## 8. Qualcomm / OnePlus KeyMint provisioning

OnePlus 13 / SM8750 public device trees expose:
- `android.hardware.security.keymint-service-qti`
- `libqtikeymint.so`
- `KmInstallKeybox`
- `librpmb.so`

Community repair tooling for OnePlus 13/15 uses the stock Qualcomm provisioning path rather than
inventing a second TEE. Public `provision_device_ids` implementations talk directly to Qualcomm
`keymaster64` through QSEECom and send the Keymaster provisioning commands.

Observed device-ID sequence:
- GET_VERSION
- SET_VERSION
- PROVISION_DEVICE_IDS
- SET_PROVISIONING_DEVICE_ID_SUCCESS

OnePlus repair reports also show that keybox provisioning and device-ID provisioning are separate
state, and that successful repair restores TEE RKP / StrongBox RKP / Widevine RKP behavior.

### TES lesson

For OP13, the strongest path is to preserve the QTI KeyMint backend and manipulate only supported
provisioning/attestation surfaces around it. Persist/RPMB provisioning is durable platform state and
should never be casually mutated by a normal TES runtime path.

---

## 9. OnePlus 13 / SM8750 real StrongBox evidence

LineageOS's public `android_device_oneplus_sm8750-common/common.mk` includes:
- `android.hardware.security.keymint3-service.strongbox.nxp`
- `android.hardware.weaver-service.nxp`

Therefore the OnePlus 13 platform has a concrete NXP StrongBox integration path in the current
custom-ROM ecosystem.

### TES architecture consequence

For OnePlus 13:

```
Android / keystore2
    |
    +-- TES routing / attestation overlay
          |
          +-- TEE       -> QTI KeyMint / TrustZone
          |
          +-- StrongBox -> NXP JavaCard KeyMint / secure element
```

The two backends must retain independent:
- service identity
- key blobs
- operation objects
- capability sets
- SharedSecret participation
- RKP identity
- lifecycle/state

---

## 10. Tencent Soter — separate TEE protocol, not just KeyMint

Repository:
- https://github.com/Tencent/soter

Relevant surfaces:
- `ISoterService.aidl`
- `SoterCoreTreble`
- `SoterCoreBeforeTreble`
- ASK / AuthKey lifecycle

Soter builds a dedicated hierarchy (device/ATTK -> ASK -> AuthKey) and exposes its own service/API.
Qualcomm devices have shipped dedicated Soter service integrations.

### TES lesson

A real "SOTER key" cannot be completed merely by making Android KeyMint RSA work. If Soter is in
scope, add a separate vendor/service bridge that preserves the device's real Soter TA hierarchy.

---

## 11. OPlus IFAA / Fingerprint Pay

Public OPlus hardware code and OnePlus device trees show a dedicated stack:
- `vendor.oplus.hardware.biometrics.fingerprintpay@1.0-service`
- `manifest_oplus_ifaa.xml`
- `libifaa_factory.so`
- `librpmbengclient.so`
- `alipay.*` secure-TA firmware

Open OPlus IFAA service code forwards raw IFAA commands into
`IFingerprintPay.ifaa_invoke_command`.

### TES lesson

IFAA is not a KeyMint alias. It is a vendor Binder -> vendor HAL -> secure TA/RPMB path.

For TES:
- do not synthesize IFAA success from KeyMint capability;
- preserve/bridge the real fingerprintpay service and TA;
- if compatibility interception is required, operate at the vendor-service command boundary, not by
  fabricating a KeyMint certificate.

---

## 12. OPlus FIDO / FIDO2

Public vendor dumps/device trees expose dedicated services:
- `vendor.oplus.hardware.fido.fidoca@1.0-service`
- `vendor.oplus.hardware.fido.fido2ca@1.0-service`

Public proprietary-file notes identify them as crypto-engine daemon/service paths that load dedicated
FIDO secure applications (e.g. FIDO TAP / CTAP TAs) through Qualcomm secure-world communication.

### TES lesson

FIDO/FIDO2 use KeyMint-like primitives but are separate secure applications and protocols.

If the OEM Key Status page is meant to reflect *real* FIDO capability, TES eventually needs a
VendorServiceBridge that can preserve/reconnect those genuine services. Changing a KeyMint
`SecurityLevel` alone cannot make FIDO2 real.

---

## 13. RPMB

RPMB participates in several distinct stacks:
- Qualcomm Keymaster attestation/keybox provisioning
- OPlus fingerprint-pay / IFAA
- secure deletion / rollback protection depending on implementation
- OEM engineering diagnostics

Qualcomm documentation and older provisioning references emphasize that RPMB key provisioning is a
one-time device operation.

### TES lesson

Never treat "RPMB key" as a normal KeyMint key alias. For runtime TES:
- consume real backend functionality where available;
- never auto-provision or overwrite physical RPMB keys;
- expose a read-only backend health/capability result to diagnostics.

For a future software-only backend, an ordinary file is not an RPMB substitute.

---

## 14. Widevine / HDCP

Widevine and HDCP live in the DRM/secure-video stack, with their own provisioning/key material.
OnePlus repair work demonstrates that fixing underlying secure provisioning can repair Widevine RKP,
but this does not make Widevine a KeyMint primitive.

### TES lesson

Do not put Widevine/HDCP implementation into `IKeyMintDevice`.
If TES grows a whole-device secure-service compatibility layer, DRM should be its own backend module.

---

## Comparison matrix

| Implementation | Real private-key hardware ownership | Real opaque KeyMint blob | HAT / SharedSecret | Secure storage / rollback | StorageKey | RKP | Real StrongBox separation | Main value to TES |
|---|---|---|---|---|---|---|---|---|
| AOSP Trusty KeyMint | Yes (TEE) | Yes | Yes | Yes | Yes | Yes | N/A (TEE reference) | Primary TEE architecture |
| NXP JavaCard KeyMint | Yes (SE/StrongBox) | Yes | Yes | Secure-element owned | Backend owned | Yes | **Yes** | Primary StrongBox architecture |
| AOSP km_compat | Backing HAL | Backing HAL | Adapts real service | Backing HAL | Backing HAL limits | platform-dependent | Preserves backend identity | Compatibility/lifecycle |
| OhMyKeymint host backend | No physical TEE | software/reference blob | Software-held in its private backend | Host-persistent SDD | Public source: no | Implements RKP logic | No physical StrongBox | State-machine ideas |
| TrickyStoreOSS generation | No | No genuine hardware blob | No real domain HAT | normal filesystem | software only | cert layer | No | Binder/API compatibility |
| KeystoreInjection | No | No | No | No | No | No | No | Provider compatibility |
| QTI stock KeyMint | **Yes** | **Yes** | **Yes** | RPMB/TEE owned | hardware owned | Yes | TEE side | OP13 TEE backend |
| NXP StrongBox on OP13 | **Yes** | **Yes** | **Yes** | SE owned | backend owned | backend-specific RKP | **Yes** | OP13 StrongBox backend |
| OPlus IFAA | secure TA | separate protocol | biometric/vendor path | RPMB involved | N/A | N/A | independent service | IFAA bridge |
| OPlus FIDO/FIDO2 | secure TA | separate protocol | authenticator/vendor path | TA owned | N/A | own provisioning | independent service | FIDO bridge |
| Tencent Soter | secure TEE on supported devices | Soter-specific | biometric/TEE | TEE-owned | N/A | Soter hierarchy | separate service | Soter bridge |

---

## Concrete TES design after this survey

### A. `RealTeeBackend`

Backs strict TEE mode with the real QTI `IKeyMintDevice/default`.

Owns nothing itself. It forwards:
- generate/import/wrapped import
- begin/update/finish
- auth-bound operations
- StorageKey
- rollback/usage-limited keys
- root-of-trust state
- maintenance operations

TES overlays only what can be overlaid without moving the private key.

### B. `RealStrongBoxBackend`

Backs strict StrongBox mode with NXP `IKeyMintDevice/strongbox`.

Must bind by service identity / VINTF, not hardware-name heuristic when native identity exists.

Also tracks the matching:
- StrongBox SharedSecret participant
- StrongBox RKP component
- NXP operation lifecycle

### C. `AttestationOverlay`

Responsible for:
- ordinary real-key leaf patch/re-root
- bare hardware ATTEST_KEY certificate reissue
- preservation of delegated A -> B signatures
- certificate-level provenance checks
- no keyBlob/private-key migration

### D. `RkpOverlay`

Per security level:
- TEE RKP
- StrongBox RKP

May replace/reissue public certificate material only. Opaque hardware keyBlob must remain unchanged.

### E. `LegacyCompatBackend`

Use AOSP `km_compat` patterns for Android 10/11/older Keymaster adaptation.

It must report the real capabilities of the backing legacy device and never manufacture a StrongBox
that does not exist.

### F. `VendorSecureServiceBridge` (separate from KeyMint)

Independent adapters for:
- OPlus IFAA / fingerprintpay
- OPlus FIDO
- OPlus FIDO2
- Soter
- later DRM/Widevine only if explicitly brought into TES scope

These bridges should preserve genuine vendor secure-world services, not map everything through
KeyMint.

---

## Immediate implementation priorities

1. Finish strict QTI TEE / NXP StrongBox separation and per-level RKP identity.
2. Add on-device conformance tests derived from AOSP/VTS rather than hand-written capability labels.
3. Validate SharedSecret service identity for the exact backend without re-running boot negotiation.
4. Keep StorageKey / rollback / auth-bound / usage state on genuine hardware.
5. Use NXP's operation lifecycle as the model for StrongBox resource handling.
6. Add a read-only backend inventory showing which *real* services were resolved and exercised.
7. Only after the KeyMint pair is stable, add separate OPlus IFAA/FIDO/Soter bridges.
8. Never auto-provision physical RPMB or persist/keybox state from ordinary runtime routing.

---

## Sources / repositories reviewed

AOSP / Google:
- https://android.googlesource.com/platform/system/keymint/
- https://android.googlesource.com/trusty/app/keymint/
- https://android.googlesource.com/trusty/app/storage/
- https://android.googlesource.com/platform/system/security/+/refs/heads/main/keystore2/src/km_compat/
- https://android.googlesource.com/platform/hardware/nxp/keymint/
- https://android.googlesource.com/platform/hardware/interfaces/+/master/security/rkp/

Community:
- https://github.com/qwq233/OhMyKeymint
- https://github.com/cytochromxxx/TrickyStore
- https://github.com/beakthoven/TrickyStoreOSS
- https://github.com/aviraxp/Zygisk-KeystoreInjection
- https://github.com/Tencent/soter
- https://github.com/FroggMaster/oneplus-fix-tee-broken

OnePlus / OPlus platform:
- https://github.com/LineageOS/android_device_oneplus_sm8750-common
- public OPlus hardware IFAA/fingerprintpay implementations and device/vendor dumps
- Qualcomm Keymaster device-ID / keybox provisioning references
