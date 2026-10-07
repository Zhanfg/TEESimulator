# OhMyKeymint 1.3.5-196 vs TEESimulator — clean-room gap audit

Date: 2026-10-07

## Scope

This note compares the supplied `OhMyKeymint-1.3.5-196-release.zip` with the current
TEESimulator `dev` line and the in-progress `feat/tee-strongbox-backends` line.
It is a behavioural/architectural study only. No OhMyKeymint source code is copied here.

Observed package identity:

- id: `oh_my_keymint`
- version: `1.3.5 (196-10113e7-release)`
- versionCode: `196`
- authors: `James Clef, ITxiao6666`
- update feed: `ITxiao6666/OhMyKeymint` changelog branch
- supplied zip: about 9.9 MiB compressed / 26 MiB extracted
- arm64 native payloads: about 23.2 MiB total

The public update feed still advertises build 195 at the time of this audit, and the
package commit id `10113e7` is not present in the public repository history searched on
2026-10-07. Treat build 196 as a package snapshot newer than the published feed, not as a
public source revision that can be diffed commit-for-commit.

## Architectural comparison

| Area | OhMyKeymint 1.3.5-196 | TEESimulator dev | TEESimulator strongbox WIP | Direction |
| --- | --- | --- | --- | --- |
| Core service model | Broad Android Keystore/KeyMint reimplementation and Binder interception | Targeted in-process reference KeyMint route inside real keystore | Same base plus hardware/StrongBox backend work | Keep TES architecture; add behavioural parity tests |
| Android support | Android 12+ | Android 10+ | Android 10+ | TES advantage; preserve |
| Target selection | Global `scoop` package list, UID-aware filter | Per-profile app assignment | Per-profile assignment + scope work | TES advantage; preserve |
| Profiles | Essentially global KeyMint identity/config | Multiple independent profiles/keyboxes | Multiple profiles + hardware mode | TES advantage; preserve |
| Key ownership | Primarily software KeyMint path with system forwarding/interception | Software reference TA for simulated keys | `hardware` / `patch` / `generation` modes; real TEE/StrongBox ownership possible | Strongbox WIP is the better long-term design |
| AIDL behavioural surface | Very broad Keystore2/KeyMint AIDL coverage | Narrower interception surface | Expanding | Highest-priority clean-room gap |
| Error semantics | Extensive detector/error-path tuning | Functional routing first | Functional hardware semantics first | Add parity corpus before timing tricks |
| Key lifecycle semantics | Database/service behaviour, key IDs, deletion/list/grant paths heavily tested | Key lifecycle is supported but smaller behavioural matrix | Re-attestation / hardware blob work added | Expand tests and explicit invariants |
| Timing behaviour | Configurable injector waits and per-TA-call random delay ranges | No dedicated timing model | No dedicated timing model | Add only after semantic parity, disabled by default |
| Injection robustness | Mature failure/retry paths; upstream crash fixes | Injector + control channel; upstream PID fast-path now being synced | Same, plus more backend state | Continue hardening; differential stress tests |
| RKP | Integrated with its broader KeyMint stack | RKP property controls in WebUI | Framework RKP AIDL + ATTEST_KEY/RKP certificate reissue research | TES WIP is strategically stronger |
| StrongBox | Exposed/status-aware; broad KeyMint implementation | Limited in dev | Explicit TEE/StrongBox backend architecture | Keep TES WIP direction |
| Keybox validation | Allows complete RSA or EC entries; EC-only RKP keyboxes can be valid | dev requires both RSA and EC | Current profile assumptions still stricter | Revisit validator semantics carefully |
| Keybox management | WebUI replacement, system picker, fallback browser, atomic validation/write | Multi-keybox import/rename/profile assignment | Same | Combine TES multi-profile UX with stronger atomic validation |
| WebUI | Vue-based, native WebUI bridge, about 20 localizations | Small modular vanilla JS WebUI | Same | Adopt resource-key i18n architecture, not OMK UI code |
| Simplified Chinese | Native string resource | Presentation translation layer currently being restored | Same | Migrate TES gradually to first-class keyed i18n |
| Security patch sync | Downloads official bulletin data and can globally reset runtime props | Per-profile attestation patch policy (`harvested`, explicit, tokens, system property) | Same | Do not move global resetprop into core; optional tool only |
| PIF fingerprint | Own Zygisk payload; Pixel profile fetch/apply | None | None | Keep out of TES core |
| ADB disabler | Included | None | None | Do not add; unrelated scope |
| Tencent/Qualcomm Soter | Beta Zygisk path + separate Qualcomm Soter HAL service | None | None | Optional separate compatibility plugin only |
| Test density | Large Rust/unit/integration corpus; public commits cite 600+ test executions | Targeted Kotlin/C++/WebUI/Rust tests | Additional VINTF/hardware-envelope tests | Major gap; raise before feature count |

## What is actually worth absorbing

### P0 — behavioural parity harness

The largest useful gap is not a missing feature button. OhMyKeymint treats Android Keystore as a
behavioural protocol whose *error values, transaction routing, object lifetime, key identifiers,
Binder reply shape and failure ordering* are observable. TEESimulator should formalise the same
idea without changing its architecture.

Build a clean-room conformance corpus around:

- every intercepted `IKeyMintDevice`, `IKeystoreService` and `IKeystoreSecurityLevel` method;
- success and malformed-parameter paths;
- unknown/missing aliases and stale key handles;
- generate/import/delete/list/grant/ungrant lifecycle ordering;
- binder death, keystore restart and injection failure;
- concurrency/race cases during generation, deletion and config replacement;
- return code and parcel-shape comparison against the real system path.

The target should be: if TES elects to intercept a call, its externally visible behaviour should
match the Android contract except for the intentionally changed attestation identity/route.

### P0 — hardware ownership invariants

Do **not** replace the strongbox WIP with OMK's broader software implementation. The TES WIP has a
more valuable property: strict `hardware` mode can keep the private key and operations in the real
TEE/StrongBox while changing only the attestation presentation. Preserve and test these invariants:

- hardware mode never silently falls back to software;
- returned KeyCharacteristics prove the requested security level;
- private hardware key material never crosses the control channel;
- certificate reissue/re-sign operations preserve the original public key;
- StrongBox requests never degrade to TEE unless the selected profile explicitly permits a
  compatibility mode.

### P0 — keybox validation and atomic replacement

OMK's package demonstrates a useful product behaviour: validate the full replacement before the
canonical keybox is atomically changed, and leave the active keybox untouched on any read/size/
UTF-8/schema/key-pair failure.

TES already has the stronger multi-keybox/profile model. Add the same transactional property to it.
Also revisit the current requirement that a keybox contain both RSA and EC. A complete EC-only
RKP-derived keybox can be legitimate. The validator should represent algorithm capability rather
than declaring the whole file invalid simply because one algorithm is absent. Profiles/calls that
need a missing algorithm must then fail explicitly and locally.

### P1 — first-class i18n

The current TES Chinese layer is deliberately safe, but it translates rendered English strings.
That is fragile when upstream wording changes. Migrate the WebUI toward stable message keys with
locale resources and fallback to English. Keep domain values, package names, protocol data, logs,
key aliases and cryptographic material outside translation.

### P1 — timing model, only after semantic parity

OMK exposes two kinds of artificial timing:

- injector-level delays for challenged generation / operation start;
- fresh per-call TA delay ranges grouped by operation, generation and control calls.

This is useful as a *testable timing model*, but should not be the first compatibility fix. Incorrect
errors or lifecycle semantics are much stronger fingerprints than a few milliseconds of latency.
If TES adds timing shaping, it should be:

- disabled by default;
- bounded and validated;
- sampled per call, not a fixed sleep;
- applied before expensive locks where possible;
- observable in diagnostics;
- covered by concurrency and Binder-thread occupancy tests;
- incapable of altering return values or routing decisions.

### P1 — injection/restart stress suite

The upstream TES `/proc` PID fast-path is good for power, but it should be paired with a stress
suite: repeatedly kill/restart keystore, race config pushes, inject failures, delayed service
registration and control-socket reconnects. Prove there is no double hook, stale-PID state, stale
control hello or old-generation readiness leak.

## What should *not* be merged into TEESimulator core

PIF spoofing, ADB disabling, developer-option hiding and general device-integrity convenience tools
are orthogonal to KeyMint/Keystore simulation. Integrating them would increase package size,
permissions, hooks, update dependencies and detection surface while making failures harder to
attribute. Keep them separate modules/plugins if ever needed.

Tencent/Qualcomm Soter is more adjacent but still a different vendor service. If required for a
specific device/application, implement it as an optional compatibility component with a narrow
interface and independent lifecycle. Do not make TES core depend on it.

Global security-patch `resetprop` is also the wrong default for TES. Per-profile attestation values
are more isolated and cause fewer system-wide side effects. An optional diagnostic/sync utility may
fetch the Android Security Bulletin, but core attestation routing should not globally rewrite build
properties merely to match a profile.

## Clean-room boundary

OhMyKeymint carries AGPL material plus additional project-specific terms and third-party components
with their own licences. Do not transplant implementation code into TEESimulator. Use only public
behaviour, Android/AOSP specifications, black-box observations and independently written tests as
requirements. For any feature inspired by this audit:

1. write the expected observable behaviour first;
2. derive the contract from AOSP documentation/source where available;
3. implement independently in TES style;
4. test against Android/real hardware behaviour, not against copied OMK internals;
5. record provenance for any third-party algorithm or protocol material.

## Recommended implementation order

1. Build the Keystore/KeyMint behavioural conformance matrix and differential test runner.
2. Add injection/restart/race stress tests and make them a CI gate.
3. Make keybox replacement transactional and capability-aware (RSA/EC/EC-only).
4. Finish and validate the existing TEE/StrongBox hardware backend line.
5. Convert WebUI localisation from rendered-string translation to message-key resources.
6. Only then evaluate optional timing shaping.
7. Keep PIF/ADB/Soter outside the core; add compatibility modules only when a concrete use case
   requires them.

## Bottom line

OhMyKeymint is currently ahead in *behavioural completeness and test depth*. TEESimulator's
strongbox branch is potentially ahead in *architecture for real hardware ownership, isolation and
multi-profile routing*. The correct strategy is therefore not to turn TES into OMK, but to combine
TES's hardware/profile architecture with OMK-level behavioural discipline and test coverage.
