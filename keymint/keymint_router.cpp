// Local IKeyMintDevice / IKeyMintOperation backed by the in-process Rust TA.
//
// The interceptor re-dispatches keystore2's KeyMint transactions to these local
// binders. The generated Bn base classes handle all parcel marshalling, so here
// we only convert between the AIDL types and the flat C ABI (teesim_km.h).
//
// Each device also wraps the real KeyMint HAL. It decides per request whether to
// simulate (target app, or one of our own key blobs) or to forward to the real
// HAL, so non-target apps and real hardware keys are never disturbed.

#include <aidl/android/hardware/security/keymint/BnKeyMintDevice.h>
#include <aidl/android/hardware/security/keymint/ErrorCode.h>
#include <aidl/android/hardware/security/keymint/BnKeyMintOperation.h>
#include <aidl/android/hardware/security/secureclock/ISecureClock.h>
#include <aidl/android/hardware/security/secureclock/TimeStampToken.h>
#include <aidl/android/hardware/security/sharedsecret/ISharedSecret.h>
#include <aidl/android/hardware/security/sharedsecret/SharedSecretParameters.h>
#include <android/binder_auto_utils.h>
#include <android/binder_ibinder.h>  // AIBinder_getCallingUid / AIBinder_getCallingPid
#include <android/binder_manager.h>  // AServiceManager_checkService
#include <unistd.h>                       // getuid / getpid

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdarg>
#include <condition_variable>
#include <ctime>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "control.h"
#include "hardware_blob_envelope.h"
#include "keymint_hook.h"
#include "km_names.h"
// The subsystem every line from this file is stamped with; see injector/include/logging.hpp.
#define LOG_SUB "km"
#include "logging.hpp"
#include "teesim_km.h"
#include "timing.h"

using namespace aidl::android::hardware::security::keymint;
namespace secureclock = aidl::android::hardware::security::secureclock;
namespace sharedsecret = aidl::android::hardware::security::sharedsecret;

namespace {

// A TA is reference-counted so an in-flight operation keeps its profile's TA
// alive even if a config reload swaps or drops that profile underneath it.
using TaPtr = std::shared_ptr<::Ta>;
TaPtr WrapTa(::Ta* ta) {
  return TaPtr(ta, [](::Ta* t) {
    if (t) teesim_km_destroy(t);
  });
}

// The stride between two Android users' uids for the same app (android.os.UserHandle.PER_USER_RANGE).
// A caller uid is userId * 100000 + appId, so this is what turns one into the other.
constexpr int32_t kPerUserRange = 100000;

// AOSP's current reference KeyMint TA permits four concurrent StrongBox operations. This counter
// applies only to TES's compatibility/software StrongBox TA; forwarded genuine StrongBox operations
// are never counted here and remain subject to the real secure element/HAL's own capacity policy.
constexpr uint32_t kStrongBoxMaxOperations = 4;
std::atomic<uint32_t> g_strongbox_active_ops{0};

bool TryAcquireStrongBoxOperation() {
  uint32_t current = g_strongbox_active_ops.load(std::memory_order_relaxed);
  while (current < kStrongBoxMaxOperations) {
    if (g_strongbox_active_ops.compare_exchange_weak(
            current, current + 1, std::memory_order_acq_rel, std::memory_order_relaxed)) {
      return true;
    }
  }
  return false;
}

void ReleaseStrongBoxOperation() {
  uint32_t previous = g_strongbox_active_ops.fetch_sub(1, std::memory_order_acq_rel);
  if (previous == 0) {
    g_strongbox_active_ops.store(0, std::memory_order_release);
    LOGW("strongbox operation counter underflow; reset to zero");
  }
}

std::string LowerAscii(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
  return value;
}


// Compare the proxy keystore2 already holds with the binder objects registered under the canonical
// KeyMint service names. AIBinder_lt defines equality by underlying binder identity, so this works
// even when two AIBinder* wrappers have different addresses. On Android 12+ this is stronger evidence
// than vendor-reported getHardwareInfo() (some OPlus stacks have mislabeled their StrongBox as TEE)
// and stronger than matching a vendor name such as NXP.
//
// A compat/backlevel KeyMint device is not registered under either native service name and returns
// no value here; those continue through getHardwareInfo()/legacy fallback.
bool SameBinderObject(AIBinder* a, AIBinder* b) {
  return a && b && !AIBinder_lt(a, b) && !AIBinder_lt(b, a);
}

bool RegisteredServiceLevel(AIBinder* binder, SecurityLevel* out,
                            std::string* service_name = nullptr) {
  struct Candidate {
    const char* name;
    SecurityLevel level;
  };
  static const Candidate kCandidates[] = {
      {"android.hardware.security.keymint.IKeyMintDevice/default",
       SecurityLevel::TRUSTED_ENVIRONMENT},
      {"android.hardware.security.keymint.IKeyMintDevice/strongbox", SecurityLevel::STRONGBOX},
  };
  for (const auto& candidate : kCandidates) {
    AIBinder* service = AServiceManager_checkService(candidate.name);
    if (!service) continue;
    const bool same = SameBinderObject(binder, service);
    AIBinder_decStrong(service);  // checkService returns an owned strong reference
    if (!same) continue;
    *out = candidate.level;
    if (service_name) *service_name = candidate.name;
    return true;
  }
  return false;
}

// One package name routed to a profile, and the Android user it is routed in. An attestation
// application id carries the package but not the user, so without `user_id` a work profile's clone of
// an app would answer to the primary user's entry and vice versa.
struct TargetPackage {
  std::string name;
  int32_t user_id = 0;
};

// A configured profile: its per-level TAs, the package names routed to it, and whether it patches the
// real hardware attestation (patch mode) or mints the whole key in the TA (generation mode).
struct Profile {
  std::string id;
  // A separate fixed-level TA per security level, mirroring how a real device runs an independent
  // KeyMint instance per level. Every op routes to the instance for the level it arrived on, so a
  // key's characteristics are always read at the level the key was minted at.
  TaPtr ta_tee;
  TaPtr ta_strongbox;
  std::vector<TargetPackage> packages;
  std::vector<int32_t> uids;  // resolved caller uids, for requests that carry no app-id to match
  // Parallel to uids[]: the package the daemon resolved each uid from, or "" for a raw uid:N or an
  // auto-included one. Only used to name the caller in the log — routing never reads it.
  std::vector<std::string> uid_names;
  bool patch_mode = false;
  // Strict hardware mode never permits the in-process TA to own the business key. The TA may still
  // re-sign a certificate, but generate/import/begin must remain on the genuine level-specific HAL.
  bool hardware_mode = false;
  TsTimingPolicy timing;

  // The TA that serves requests arriving at `level`. Software-level KeyMint is never wrapped, so any
  // non-StrongBox level maps to the TrustedEnvironment instance.
  const TaPtr& TaFor(SecurityLevel level) const {
    return level == SecurityLevel::STRONGBOX ? ta_strongbox : ta_tee;
  }
};

// Live routing, swapped atomically by teesim_cfg_commit under g_cfg_mu.
std::mutex g_cfg_mu;
std::vector<Profile> g_profiles;
// Signalled by teesim_cfg_commit. Operations on one of our own key blobs wait on this rather than
// failing while the daemon has not pushed a config yet; see WaitForDefaultTa.
std::condition_variable g_cfg_cv;
bool g_strongbox_ok = false;  // device can patch real StrongBox keys; else StrongBox forces generation
// The device-wide MODULE_HASH to seed a freshly built TA with, so a generation-mode key carries the
// tag keystore2 only sends once per boot (and never resends to a TA built afterwards). Preference:
// the exact bytes keystore2 pushed via setAdditionalAttestationInfo, captured below; the daemon's own
// computed value (g_stage_module_hash) is only a fallback for when we never saw that one-shot call.
// Guarded by g_cfg_mu. Empty until either source provides one.
std::vector<uint8_t> g_module_hash;

// Monotonic/replaceable device lifecycle state that a newly-resolved real backend must receive.
// earlyBootEnded is one-way for the entire boot; additional attestation info (notably MODULE_HASH)
// is the latest device-wide set keystore2 supplied. Destructive commands such as deleteAllKeys are
// intentionally NOT queued/replayed.
std::mutex g_hw_lifecycle_mu;
bool g_hw_early_boot_ended = false;
std::vector<KeyParameter> g_hw_additional_attestation_info;

// Staging state built up by teesim_cfg_begin/add_profile before the swap.
std::vector<Profile> g_staging;
std::vector<uint8_t> g_stage_vb_key;
std::vector<uint8_t> g_stage_vb_hash;
std::vector<uint8_t> g_stage_module_hash;  // MODULE_HASH to seed each TA with at creation (may be empty)
bool g_stage_locked = true;
int32_t g_stage_vb_state = 0;
bool g_stage_strongbox_ok = false;
int32_t g_stage_attest_version_tee = 400;
int32_t g_stage_attest_version_strongbox = 300;

// --- Per-caller usage stats --------------------------------------------------
// Every app that asks us for a key this boot is recorded here from generateKey,
// so the daemon can surface a "Recent" group and a frequency ordering in the
// scope picker. Keyed by caller uid because a uid outlives a single request; the
// daemon maps uid->package (uids get reassigned across installs, packages are
// stable). This is a hot path, so the record is a short locked map update with
// no I/O — never touch the crypto path's latency.
struct UsageEntry {
  uint64_t count = 0;         // cumulative generateKey requests from this uid since load
  uint64_t last_boot_ms = 0;  // CLOCK_BOOTTIME (ms) of the most recent request
  std::string pkg;            // best-effort package hint, usually empty (daemon resolves uid->pkg)
};
std::mutex g_usage_mu;
std::map<int32_t, UsageEntry> g_usage;

// Milliseconds on CLOCK_BOOTTIME: a monotonic clock that keeps counting across
// suspend, matching the daemon's SystemClock.elapsedRealtime so it can convert
// our lastBootMs back to a wall-clock instant.
uint64_t NowBootMs() {
  struct timespec ts{};
  clock_gettime(CLOCK_BOOTTIME, &ts);
  return static_cast<uint64_t>(ts.tv_sec) * 1000u + static_cast<uint64_t>(ts.tv_nsec) / 1000000u;
}

// Milliseconds on CLOCK_MONOTONIC, for the "how long did this take" fields. Deliberately not
// NowBootMs: the usage stats need a clock that keeps counting across suspend, a duration needs one
// that does not.
uint64_t NowMonoMs() {
  struct timespec ts{};
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return static_cast<uint64_t>(ts.tv_sec) * 1000u + static_cast<uint64_t>(ts.tv_nsec) / 1000000u;
}

// A stopwatch for one span, so the log can say whether a hooked call added latency even below the
// ~500ms threshold where libbinder's own slow-transaction warning fires.
struct Elapsed {
  uint64_t t0 = NowMonoMs();
  unsigned long long Ms() const { return NowMonoMs() - t0; }
};

// The security level as the name a reader knows it by, rather than the AIDL's ordinal.
const char* LevelName(SecurityLevel level) {
  switch (level) {
    case SecurityLevel::SOFTWARE: return "SW";
    case SecurityLevel::TRUSTED_ENVIRONMENT: return "TEE";
    case SecurityLevel::STRONGBOX: return "StrongBox";
    case SecurityLevel::KEYSTORE: return "keystore";
    default: return "?";
  }
}

struct HardwareBackendDomain {
  SecurityLevel level = SecurityLevel::SOFTWARE;
  std::shared_ptr<IKeyMintDevice> keymint;

  // Canonical service identity is authoritative when present. Backlevel km_compat paths may not
  // have one, in which case reported HardwareInfo remains the best available evidence.
  std::string keymint_service;
  std::string shared_secret_service;
  std::string secure_clock_service;
  std::string rkp_instance;
  std::shared_ptr<sharedsecret::ISharedSecret> shared_secret;
  std::shared_ptr<secureclock::ISecureClock> secure_clock;
  bool shared_secret_declared = false;
  bool secure_clock_declared = false;
  bool rkp_declared = false;
  std::string keymint_name;
  std::string keymint_author;
  bool canonical_identity = false;
  bool remote = false;

  // Every newly-resolved KeyMint binder gets a monotonically increasing epoch. A keystore2/HAL
  // restart therefore creates a new domain even if the security level and service name are the same.
  // Operations keep the domain they were created under, which makes stale-backend failures
  // attributable instead of silently looking like a generic StrongBox/TEE failure.
  uint64_t epoch = 0;

  // Remote binder liveness is part of the security-domain state. A dead StrongBox/TEE service is not
  // "temporarily software": strict hardware must stop treating this domain as available until
  // keystore2 resolves a new binder and MakeBackendDomain assigns a new epoch.
  std::atomic<bool> dead{false};
  std::atomic<bool> early_boot_synced{true};
  std::atomic<bool> additional_info_synced{true};
  ndk::SpAIBinder binder;
  ndk::ScopedAIBinder_DeathRecipient death_recipient;
  bool death_linked = false;

  ~HardwareBackendDomain() {
    // The death-recipient cookie is `this`; unlink before destruction so no callback can observe a
    // freed domain. This mirrors the explicit unlink performed by NXP's StrongBox OMAPI transport.
    if (death_linked && binder.get() && death_recipient.get()) {
      const binder_status_t st =
          AIBinder_unlinkToDeath(binder.get(), death_recipient.get(), this);
      if (st != STATUS_OK && st != STATUS_DEAD_OBJECT && st != STATUS_NAME_NOT_FOUND) {
        LOGD("backend-domain: unlinkToDeath %s#%llu returned %d", Label(),
             static_cast<unsigned long long>(epoch), st);
      }
      death_linked = false;
    }
  }

  const char* Label() const { return LevelName(level); }
};

std::atomic<uint64_t> g_backend_epoch{1};
std::mutex g_backend_domain_mu;
std::map<int32_t, std::weak_ptr<HardwareBackendDomain>> g_backend_domains;

void BackendBinderDied(void* cookie) {
  auto* domain = static_cast<HardwareBackendDomain*>(cookie);
  if (!domain) return;

  const bool was_dead = domain->dead.exchange(true, std::memory_order_acq_rel);
  if (was_dead) return;

  LOGE("backend-domain: %s#%llu binder died (service=%s hal='%s'/'%s'); "
       "strict hardware domain is unavailable until keystore2 resolves a new binder",
       domain->Label(), static_cast<unsigned long long>(domain->epoch),
       domain->keymint_service.empty() ? "<compat/unknown>" : domain->keymint_service.c_str(),
       domain->keymint_name.c_str(), domain->keymint_author.c_str());

  std::lock_guard<std::mutex> lk(g_backend_domain_mu);
  auto it = g_backend_domains.find(static_cast<int32_t>(domain->level));
  if (it == g_backend_domains.end()) return;
  auto current = it->second.lock();
  if (current.get() == domain) g_backend_domains.erase(it);
}

template <typename Interface>
std::shared_ptr<Interface> BindAuxService(const std::string& name, bool* declared) {
  if (declared) *declared = false;
  if (name.empty()) return {};

  // Android 12+ is the only runtime that loads this KeyMint interceptor. A declared service may
  // still be lazy/not started; checkService deliberately does not start it. That keeps TES from
  // perturbing Android's own trust-service startup/SharedSecret negotiation just to collect
  // evidence about the backend domain.
  const bool is_declared = AServiceManager_isDeclared(name.c_str());
  if (declared) *declared = is_declared;
  if (!is_declared) return {};

  AIBinder* raw = AServiceManager_checkService(name.c_str());
  if (!raw) return {};
  ndk::SpAIBinder binder(raw);  // adopts checkService's strong reference
  return Interface::fromBinder(binder);
}

std::shared_ptr<HardwareBackendDomain> MakeBackendDomain(
    SecurityLevel level, std::shared_ptr<IKeyMintDevice> keymint,
    std::string keymint_service, bool canonical_identity, bool remote,
    std::string keymint_name, std::string keymint_author) {
  auto domain = std::make_shared<HardwareBackendDomain>();
  domain->level = level;
  domain->keymint = std::move(keymint);
  domain->keymint_service = std::move(keymint_service);
  domain->canonical_identity = canonical_identity;
  domain->remote = remote;
  domain->keymint_name = std::move(keymint_name);
  domain->keymint_author = std::move(keymint_author);
  domain->epoch = g_backend_epoch.fetch_add(1, std::memory_order_relaxed);

  if (level == SecurityLevel::STRONGBOX) {
    domain->shared_secret_service =
        "android.hardware.security.sharedsecret.ISharedSecret/strongbox";
    domain->rkp_instance = "strongbox";
  } else if (level == SecurityLevel::TRUSTED_ENVIRONMENT) {
    domain->shared_secret_service =
        "android.hardware.security.sharedsecret.ISharedSecret/default";
    domain->rkp_instance = "default";
  }
  // SecureClock is device-wide in AOSP; StrongBox/TEE may both rely on the same published instance.
  domain->secure_clock_service =
      "android.hardware.security.secureclock.ISecureClock/default";

  // Bind the auxiliary trust services as members of this backend domain. Do not call
  // computeSharedSecret(): Android owns that N-party negotiation during boot and a late participant
  // would be wrong. We retain the live interfaces only for side-effect-free health/provenance
  // checks. Absence is not automatically fatal: AOSP allows a security environment to use an
  // internal shared-HMAC/secure-time path, and SecureClock itself is optional.
  domain->shared_secret =
      BindAuxService<sharedsecret::ISharedSecret>(domain->shared_secret_service,
                                                  &domain->shared_secret_declared);
  domain->secure_clock =
      BindAuxService<secureclock::ISecureClock>(domain->secure_clock_service,
                                                &domain->secure_clock_declared);

  // RKP is matched by security level exactly as keystore2 does. StrongBox RKP is optional, so record
  // declaration separately from the KeyMint backend's existence.
  if (!domain->rkp_instance.empty()) {
    const std::string rkp_service =
        std::string("android.hardware.security.keymint.IRemotelyProvisionedComponent/") +
        domain->rkp_instance;
    domain->rkp_declared = AServiceManager_isDeclared(rkp_service.c_str());
  }

  LOGI("backend-domain: %s#%llu aux sharedsecret=%s(%s,bound=%d) secureclock=%s(%s,bound=%d) "
       "rkp=%s(declared=%d)",
       domain->Label(), static_cast<unsigned long long>(domain->epoch),
       domain->shared_secret_service.empty() ? "<none>" : domain->shared_secret_service.c_str(),
       domain->shared_secret_declared ? "declared" : "not-declared",
       domain->shared_secret ? 1 : 0,
       domain->secure_clock_service.empty() ? "<none>" : domain->secure_clock_service.c_str(),
       domain->secure_clock_declared ? "declared" : "not-declared",
       domain->secure_clock ? 1 : 0,
       domain->rkp_instance.empty() ? "<none>" : domain->rkp_instance.c_str(),
       domain->rkp_declared ? 1 : 0);

  if (domain->keymint) {
    domain->binder = domain->keymint->asBinder();
  }
  if (domain->remote && domain->binder.get()) {
    domain->death_recipient = ndk::ScopedAIBinder_DeathRecipient(
        AIBinder_DeathRecipient_new(BackendBinderDied));
    if (domain->death_recipient.get()) {
      const binder_status_t linked =
          AIBinder_linkToDeath(domain->binder.get(), domain->death_recipient.get(), domain.get());
      if (linked == STATUS_OK) {
        domain->death_linked = true;
      } else {
        LOGW("backend-domain: could not link death recipient for %s#%llu service=%s status=%d",
             domain->Label(), static_cast<unsigned long long>(domain->epoch),
             domain->keymint_service.empty() ? "<compat/unknown>" : domain->keymint_service.c_str(),
             linked);
      }
    }
  }

  {
    std::lock_guard<std::mutex> lk(g_backend_domain_mu);
    g_backend_domains[static_cast<int32_t>(level)] = domain;
  }
  return domain;
}

// Record one key request from `caller_uid` (target or not). Cheap by design: the
// daemon does the uid->package resolution, so we only bump the count and stamp
// the time. A caller with no valid uid (-1) is skipped.
void RecordUsage(int32_t caller_uid) {
  if (caller_uid < 0) return;
  std::lock_guard<std::mutex> lk(g_usage_mu);
  UsageEntry& e = g_usage[caller_uid];
  ++e.count;
  e.last_boot_ms = NowBootMs();
}

// RAII guard: mark the current thread as forwarding to the real HAL.
struct ForwardGuard {
  ForwardGuard() { teesim_hook_set_forwarding(true); }
  ~ForwardGuard() { teesim_hook_set_forwarding(false); }
};

// ReplayBackendLifecycleState is intentionally located next to the backend-domain lifecycle state,
// before the general KeyMint conversion/logging helpers. Declare the two small status helpers here so
// the lifecycle code can use the same error formatting without depending on source-order accidents.
ndk::ScopedAStatus Status(int32_t code);
std::string StatusDesc(const ndk::ScopedAStatus& st);

void ReplayBackendLifecycleState(const std::shared_ptr<HardwareBackendDomain>& domain) {
  if (!domain || !domain->keymint || domain->dead.load(std::memory_order_acquire)) return;

  bool early_boot_ended = false;
  std::vector<KeyParameter> additional_info;
  {
    std::lock_guard<std::mutex> lk(g_hw_lifecycle_mu);
    early_boot_ended = g_hw_early_boot_ended;
    additional_info = g_hw_additional_attestation_info;
  }

  bool early_synced = true;
  bool info_synced = true;
  if (early_boot_ended) {
    ForwardGuard g;
    auto st = domain->keymint->earlyBootEnded();
    if (!st.isOk()) {
      early_synced = false;
      LOGW("backend-domain: %s#%llu failed to replay earlyBootEnded: %s",
           domain->Label(), static_cast<unsigned long long>(domain->epoch),
           StatusDesc(st).c_str());
    } else {
      LOGI("backend-domain: %s#%llu replayed earlyBootEnded",
           domain->Label(), static_cast<unsigned long long>(domain->epoch));
    }
  }

  if (!additional_info.empty()) {
    ForwardGuard g;
    auto st = domain->keymint->setAdditionalAttestationInfo(additional_info);
    if (!st.isOk()) {
      info_synced = false;
      LOGW("backend-domain: %s#%llu failed to replay additional attestation info: %s",
           domain->Label(), static_cast<unsigned long long>(domain->epoch),
           StatusDesc(st).c_str());
    } else {
      LOGI("backend-domain: %s#%llu replayed %zu additional attestation parameter(s)",
           domain->Label(), static_cast<unsigned long long>(domain->epoch),
           additional_info.size());
    }
  }

  domain->early_boot_synced.store(early_synced, std::memory_order_release);
  domain->additional_info_synced.store(info_synced, std::memory_order_release);
}

ndk::ScopedAStatus RequireBackendLifecycleSynced(const char* what,
                                                 const HardwareBackendDomain& domain) {
  if (domain.dead.load(std::memory_order_acquire)) {
    LOGE("%s: backend %s#%llu is dead", what, domain.Label(),
         static_cast<unsigned long long>(domain.epoch));
    return ndk::ScopedAStatus::fromStatus(STATUS_DEAD_OBJECT);
  }
  const bool early_ok = domain.early_boot_synced.load(std::memory_order_acquire);
  const bool info_ok = domain.additional_info_synced.load(std::memory_order_acquire);
  if (!early_ok || !info_ok) {
    LOGE("%s: backend %s#%llu lifecycle state unsynchronized (earlyBoot=%d additionalInfo=%d); "
         "strict hardware operation refused",
         what, domain.Label(), static_cast<unsigned long long>(domain.epoch), early_ok, info_ok);
    return Status(-1000);  // KeyMint UNKNOWN_ERROR rather than silently using stale secure state.
  }
  return ndk::ScopedAStatus::ok();
}

// The profile matched to this request by its ATTESTATION_APPLICATION_ID: the TA to serve it with and
// whether that profile is in patch mode. `ta` is null when the request is not for any target app.
struct RequestTarget {
  TaPtr ta;
  bool patch_mode = false;
  bool hardware_mode = false;
  // The profile's id, for the log: on a device with more than one profile it says which keybox
  // signed a chain.
  std::string id;
  TsTimingPolicy timing;
};

RequestTarget ProfileForRequest(const std::vector<KeyParameter>& params, uid_t caller_uid,
                                SecurityLevel level) {
  std::lock_guard<std::mutex> lk(g_cfg_mu);
  if (g_profiles.empty()) return {};
  // The Android user the request came from, or -1 when the caller is unknown (no binder transaction
  // in flight). An unknown user cannot contradict a name match, so it accepts any entry's user.
  const int32_t caller_user =
      caller_uid == static_cast<uid_t>(-1) ? -1 : static_cast<int32_t>(caller_uid) / kPerUserRange;
  // Primary match: the ATTESTATION_APPLICATION_ID the app embeds in the request names its package.
  // The blob names only the package, so the caller's user is what separates two users' copies of one
  // app — a work profile's Play Store must not pick up the entry written for the primary user's.
  for (const auto& p : params) {
    if (p.tag != Tag::ATTESTATION_APPLICATION_ID) continue;
    if (p.value.getTag() != KeyParameterValue::blob) continue;
    const auto& id = p.value.get<KeyParameterValue::blob>();
    std::string hay(id.begin(), id.end());
    for (const auto& prof : g_profiles) {
      for (const auto& pkg : prof.packages) {
        if (hay.find(pkg.name) == std::string::npos) continue;
        if (caller_user >= 0 && pkg.user_id != caller_user) {
          // A seam, not an outcome: it fires per candidate package on every request that carries an
          // attestation application id, and says nothing a reader wants unless routing is the thing
          // under investigation.
          LOGD("ProfileForRequest: '%s' matches profile '%s' for user %d, not the caller's user "
               "%d; skipped",
               pkg.name.c_str(), prof.id.c_str(), pkg.user_id, caller_user);
          continue;
        }
        return {prof.TaFor(level), prof.patch_mode, prof.hardware_mode, prof.id, prof.timing};
      }
    }
  }
  // Fallback match: the caller's uid. An app creating an attestation KEY does so unattested — no
  // challenge, no app-id — so there is nothing to name-match, yet we must still route it to the app's
  // profile (and mint it in the TA) or the key it later attests is signed by a key we do not hold.
  if (caller_uid != static_cast<uid_t>(-1)) {
    for (const auto& prof : g_profiles) {
      for (int32_t uid : prof.uids) {
        if (static_cast<uid_t>(uid) == caller_uid)
          return {prof.TaFor(level), prof.patch_mode, prof.hardware_mode, prof.id, prof.timing};
      }
    }
  }
  return {};
}

bool HasParamTag(const std::vector<KeyParameter>& params, Tag tag) {
  return std::any_of(params.begin(), params.end(), [tag](const KeyParameter& p) { return p.tag == tag; });
}

uint32_t ApplyTimingDelay(const TsDelayRange& range, const char* category, const std::string& profile) {
  const uint32_t ms = TsSleepDelay(range);
  if (ms != 0) {
    LOGD("timing: profile=%s category=%s delay=%ums", profile.empty() ? "-" : profile.c_str(),
         category, ms);
  }
  return ms;
}

// The log prefix naming the request a hooked call is serving: "[10316 com.snapchat.android r3c81] ",
// or "[10316 r3c81] " when no configured package resolved to that uid. Stamped once per entry point;
// every line the call logs then carries it, which is what makes an operation attributable to an app
// instead of having to be inferred from what was logged next to it on an interleaved thread.
//
// AIBinder_getCallingUid returns getuid() when no transaction is in flight, never -1, so a uid alone
// cannot tell keystore2's own work (its key garbage collection, say) from an app running as
// AID_KEYSTORE. Pairing the uid with the pid says which it is.
std::string PackageNameFor(int32_t uid) {
  std::lock_guard<std::mutex> lk(g_cfg_mu);
  for (const auto& prof : g_profiles) {
    for (size_t i = 0; i < prof.uids.size(); ++i) {
      if (prof.uids[i] != uid) continue;
      if (i < prof.uid_names.size()) return prof.uid_names[i];
      return std::string();
    }
  }
  // No exact match: a secondary-user caller carries uid = user * 100000 + app_id and shares its
  // package with the primary-user entry of the same app id, so match on app id to name it rather
  // than log a bare uid (a Private-space app forwards here as e.g. 1010156 for app id 10156). The
  // name carries the user as "pkg@<user>" to mark it a cross-user instance, not a configured
  // target. Log line only; routing keys off the exact uid, so it never widens a profile's scope.
  const int32_t app_id = uid % 100000;
  for (const auto& prof : g_profiles) {
    for (size_t i = 0; i < prof.uids.size() && i < prof.uid_names.size(); ++i) {
      if (prof.uids[i] % 100000 == app_id && !prof.uid_names[i].empty()) {
        return prof.uid_names[i] + "@" + std::to_string(uid / 100000);
      }
    }
  }
  return std::string();
}

// A fresh context for the request now entering. `rid` joins this request's lines across the router,
// the TA and both languages; it is minted here because this is the one place every hooked call
// passes through.
std::string RequestCtx() {
  char rid[16];
  snprintf(rid, sizeof(rid), "r%04x", teesim_log_new_rid());
  const uid_t caller_uid = AIBinder_getCallingUid();
  // AIBinder_getCallingPid is __INTRODUCED_IN(29), the same floor as getCallingUid — unlike
  // AIBinder_isHandlingTransaction, which is 33 and would be a null weak symbol on Android 12.
  if (caller_uid == getuid() && AIBinder_getCallingPid() == getpid()) {
    return std::string("[self ") + rid + "] ";
  }
  const int32_t uid = static_cast<int32_t>(caller_uid);
  std::string tag = "[" + std::to_string(uid);
  const std::string name = PackageNameFor(uid);
  if (!name.empty()) tag += " " + name;
  return tag + " " + rid + "] ";
}

// How long an operation on one of our own key blobs waits for the daemon's first config push.
constexpr auto kConfigWait = std::chrono::seconds(8);

// ErrorCode::HARDWARE_NOT_YET_AVAILABLE. Returned when a key of ours outlives the wait below: it says
// "come back later", where the UNIMPLEMENTED we used to return says "this key is unusable" and pushes
// the app into deleting and regenerating it.
constexpr int32_t kNotYetAvailable = -85;

// The TA used for operations on an existing blob of ours (begin/upgrade/etc.), at the level the op
// arrived on. Any profile's TA can decrypt any of our blobs (the KEK is level- and profile-
// independent), but the level must match so the reference TA finds the key's characteristics at its
// own level; the front profile's instance for `level` serves as that default.
//
// It waits out the window between this library taking over keystore2's KeyMint and the daemon
// pushing the config that builds those TAs. keystore2 resolves KeyMint — and apps start using their
// keys — within a second of boot, while the daemon still has to harvest and validate before it can
// push. A key of OURS touched in that window has no TA to serve it, and the hard error we used to
// return reads to keystore2 (and to the app) as "this key is broken": the app's recovery is to delete
// the alias and generate a fresh key, which silently destroys everything the old key had encrypted.
// Blocking the caller for a moment instead costs a stall at boot and keeps the key.
TaPtr WaitForDefaultTa(SecurityLevel level) {
  // Latched once the wait has run out, so a daemon that never pushes (no keybox, say) costs one
  // stall rather than one per call: every app touching a key of ours would otherwise park a
  // keystore2 binder thread for the full timeout and could starve the pool at boot.
  static bool gave_up = false;
  std::unique_lock<std::mutex> lk(g_cfg_mu);
  if (g_profiles.empty()) {
    if (gave_up) return {};
    LOGW("WaitForDefaultTa: no profile configured yet; holding an operation on one of our keys for up "
         "to %llds rather than failing it",
         static_cast<long long>(kConfigWait.count()));
    g_cfg_cv.wait_for(lk, kConfigWait, [] { return !g_profiles.empty(); });
    if (g_profiles.empty()) {
      gave_up = true;
      LOGE("WaitForDefaultTa: still no profile after waiting; the daemon never pushed a config (missing "
           "or invalid keybox?); reporting the hardware as not yet available, and an app that gives "
           "up here may regenerate its key and lose whatever it had encrypted");
      return {};
    }
    LOGI("WaitForDefaultTa: config arrived while waiting; serving the operation");
  }
  gave_up = false;
  return g_profiles.front().TaFor(level);
}

// A snapshot of every configured profile's TA, for device-state transitions (earlyBootEnded /
// setAdditionalAttestationInfo) that must reach all our keys, not just the default profile. The list
// is copied under the config lock so the calls themselves run unlocked.
std::vector<TaPtr> AllProfileTas() {
  std::lock_guard<std::mutex> lk(g_cfg_mu);
  std::vector<TaPtr> tas;
  tas.reserve(g_profiles.size() * 2);
  for (const auto& p : g_profiles) {
    if (p.ta_tee) tas.push_back(p.ta_tee);
    if (p.ta_strongbox) tas.push_back(p.ta_strongbox);
  }
  return tas;
}

// Record `hash` on `ta` as Tag::MODULE_HASH so a generation-mode key it mints carries the module
// hash. No-op for an empty hash. Setting the value a TA already holds is idempotent in the reference
// TA (a repeat of the same bytes is ignored), so the later keystore2 forward over the same value is
// harmless; only a genuinely different value is rejected, which this logs.
void SeedModuleHash(const TaPtr& ta, const std::vector<uint8_t>& hash) {
  if (hash.empty() || !ta) return;
  KmParam p{};
  p.tag = static_cast<uint32_t>(Tag::MODULE_HASH);
  p.blob = hash.data();
  p.blob_len = hash.size();
  int32_t rc = teesim_km_set_additional_attestation_info(ta.get(), &p, 1);
  if (rc != 0) LOGW("SeedModuleHash: TA rejected rc=%d(%s)", rc, teesim_km_err_name(rc));
}

// --- AIDL KeyParameter <-> flat KmParam --------------------------------------

KmParam ToKm(const KeyParameter& kp) {
  KmParam k{};
  k.tag = static_cast<uint32_t>(kp.tag);
  switch (kp.value.getTag()) {
    case KeyParameterValue::algorithm:
      k.int_value = static_cast<int64_t>(kp.value.get<KeyParameterValue::algorithm>());
      break;
    case KeyParameterValue::blockMode:
      k.int_value = static_cast<int64_t>(kp.value.get<KeyParameterValue::blockMode>());
      break;
    case KeyParameterValue::paddingMode:
      k.int_value = static_cast<int64_t>(kp.value.get<KeyParameterValue::paddingMode>());
      break;
    case KeyParameterValue::digest:
      k.int_value = static_cast<int64_t>(kp.value.get<KeyParameterValue::digest>());
      break;
    case KeyParameterValue::ecCurve:
      k.int_value = static_cast<int64_t>(kp.value.get<KeyParameterValue::ecCurve>());
      break;
    case KeyParameterValue::origin:
      k.int_value = static_cast<int64_t>(kp.value.get<KeyParameterValue::origin>());
      break;
    case KeyParameterValue::keyPurpose:
      k.int_value = static_cast<int64_t>(kp.value.get<KeyParameterValue::keyPurpose>());
      break;
    case KeyParameterValue::hardwareAuthenticatorType:
      k.int_value = static_cast<int64_t>(kp.value.get<KeyParameterValue::hardwareAuthenticatorType>());
      break;
    case KeyParameterValue::securityLevel:
      k.int_value = static_cast<int64_t>(kp.value.get<KeyParameterValue::securityLevel>());
      break;
    case KeyParameterValue::boolValue:
      k.int_value = kp.value.get<KeyParameterValue::boolValue>() ? 1 : 0;
      break;
    case KeyParameterValue::integer:
      k.int_value = kp.value.get<KeyParameterValue::integer>();
      break;
    case KeyParameterValue::longInteger:
      k.int_value = kp.value.get<KeyParameterValue::longInteger>();
      break;
    case KeyParameterValue::dateTime:
      k.int_value = kp.value.get<KeyParameterValue::dateTime>();
      break;
    case KeyParameterValue::blob: {
      const auto& b = kp.value.get<KeyParameterValue::blob>();
      k.blob = b.data();
      k.blob_len = b.size();
      break;
    }
    default:
      break;
  }
  return k;
}

std::vector<KmParam> ToKmVec(const std::vector<KeyParameter>& params) {
  std::vector<KmParam> out;
  out.reserve(params.size());
  for (const auto& p : params) out.push_back(ToKm(p));
  return out;
}

KeyParameter FromKm(const KmParam& k) {
  KeyParameter kp;
  kp.tag = static_cast<Tag>(k.tag);
  switch (kp.tag) {
    case Tag::ALGORITHM:
      kp.value.set<KeyParameterValue::algorithm>(static_cast<Algorithm>(k.int_value));
      return kp;
    case Tag::BLOCK_MODE:
      kp.value.set<KeyParameterValue::blockMode>(static_cast<BlockMode>(k.int_value));
      return kp;
    case Tag::PADDING:
      kp.value.set<KeyParameterValue::paddingMode>(static_cast<PaddingMode>(k.int_value));
      return kp;
    case Tag::DIGEST:
    case Tag::RSA_OAEP_MGF_DIGEST:
      kp.value.set<KeyParameterValue::digest>(static_cast<Digest>(k.int_value));
      return kp;
    case Tag::EC_CURVE:
      kp.value.set<KeyParameterValue::ecCurve>(static_cast<EcCurve>(k.int_value));
      return kp;
    case Tag::ORIGIN:
      kp.value.set<KeyParameterValue::origin>(static_cast<KeyOrigin>(k.int_value));
      return kp;
    case Tag::PURPOSE:
      kp.value.set<KeyParameterValue::keyPurpose>(static_cast<KeyPurpose>(k.int_value));
      return kp;
    case Tag::USER_AUTH_TYPE:
      kp.value.set<KeyParameterValue::hardwareAuthenticatorType>(
          static_cast<HardwareAuthenticatorType>(k.int_value));
      return kp;
    default:
      break;
  }
  // The remaining tags map by their flat value kind (the classifier the Rust TA
  // owns), so the width/signedness table lives in one place. The specific ENUM
  // tags handled above keep their dedicated union fields; everything else is a
  // bool, a byte array, a date, a long, or a plain 32-bit integer.
  switch (teesim_km_tag_value_kind(k.tag)) {
    case KM_VALUE_BOOL:
      kp.value.set<KeyParameterValue::boolValue>(true);
      break;
    case KM_VALUE_BYTES:
      kp.value.set<KeyParameterValue::blob>(std::vector<uint8_t>(k.blob, k.blob + k.blob_len));
      break;
    case KM_VALUE_INT64:  // DATE
      kp.value.set<KeyParameterValue::dateTime>(k.int_value);
      break;
    case KM_VALUE_UINT64:  // ULONG/ULONG_REP
      kp.value.set<KeyParameterValue::longInteger>(k.int_value);
      break;
    default:  // INT32/UINT32 enums and integers
      kp.value.set<KeyParameterValue::integer>(static_cast<int32_t>(k.int_value));
      break;
  }
  return kp;
}

ndk::ScopedAStatus Status(int32_t code) {
  return code == 0 ? ndk::ScopedAStatus::ok()
                   : ndk::ScopedAStatus::fromServiceSpecificError(code);
}

// A forwarded call's outcome, in the form the log wants it: the KeyMint status by number and by
// name. A transaction that died before reaching the HAL carries no service-specific error at all — its
// getServiceSpecificError() is 0, which reads as success — so that case is reported as the binder
// exception it actually is.
std::string StatusDesc(const ndk::ScopedAStatus& st) {
  if (st.isOk()) return "rc=0";
  char buf[96];
  if (st.getExceptionCode() == EX_SERVICE_SPECIFIC) {
    const int32_t rc = st.getServiceSpecificError();
    snprintf(buf, sizeof(buf), "rc=%d(%s)", rc, teesim_km_err_name(rc));
  } else {
    snprintf(buf, sizeof(buf), "binder_exc=%d transaction=%d", st.getExceptionCode(),
             st.getStatus());
  }
  return std::string(buf);
}

// A call we can neither serve nor forward. UNIMPLEMENTED is what the caller sees; saying so is what
// distinguishes "the module declined" from "the module was never asked".
ndk::ScopedAStatus NoRealHal(const char* what) {
  LOGW("%s: FAILED, not ours to serve and no real HAL to forward to; reporting rc=-100(%s)", what,
       teesim_km_err_name(-100));
  return Status(-100);
}

// The reply to an operation on one of our keys that arrives with no TA to serve it.
//
// WaitForDefaultTa latches `gave_up` after its first timeout, so on a device where the daemon never
// pushes a config this is not one stall but the permanent answer for every operation on every key of
// ours. An app that concludes its key is broken may regenerate it, so every occurrence is logged.
ndk::ScopedAStatus NoTa(const char* what) {
  LOGW("%s: FAILED, no TA for this level yet; reporting rc=%d(%s); an app that gives up here may "
       "regenerate its key and lose whatever it had encrypted",
       what, kNotYetAvailable, teesim_km_err_name(kNotYetAvailable));
  return Status(kNotYetAvailable);
}

void FillCreationResult(TsCreationResult* res, KeyCreationResult* out) {
  const uint8_t* blob = nullptr;
  size_t blob_len = 0;
  teesim_km_result_key_blob(res, &blob, &blob_len);
  out->keyBlob.assign(blob, blob + blob_len);

  size_t n_certs = teesim_km_result_num_certs(res);
  out->certificateChain.resize(n_certs);
  for (size_t i = 0; i < n_certs; ++i) {
    const uint8_t* c = nullptr;
    size_t clen = 0;
    teesim_km_result_cert(res, i, &c, &clen);
    out->certificateChain[i].encodedCertificate.assign(c, c + clen);
  }

  size_t n_chars = teesim_km_result_num_chars(res);
  out->keyCharacteristics.resize(n_chars);
  for (size_t ci = 0; ci < n_chars; ++ci) {
    int32_t level = 0;
    size_t n_params = teesim_km_result_char(res, ci, &level);
    out->keyCharacteristics[ci].securityLevel = static_cast<SecurityLevel>(level);
    out->keyCharacteristics[ci].authorizations.reserve(n_params);
    for (size_t pi = 0; pi < n_params; ++pi) {
      KmParam km{};
      teesim_km_result_char_param(res, ci, pi, &km);
      out->keyCharacteristics[ci].authorizations.push_back(FromKm(km));
    }
  }
}

// True if `blob` is one of our key blobs.
bool IsOurs(const std::vector<uint8_t>& blob) {
  return teesim_km_is_marked(blob.data(), blob.size());
}

// Defined below with the operation tracing helpers.
std::string BlobTag(const std::vector<uint8_t>& blob);

// Persist the security-domain owner alongside strict-hardware key blobs.
//
// The byte-level codec lives in common/hardware_blob_envelope.h so host CI executes the exact same
// format used here. This Android-facing adapter adds SecurityLevel/domain checks and, critically,
// refuses to wrap or unwrap one of the in-process TA's marked software blobs as hardware.
std::vector<uint8_t> WrapHardwareBlob(SecurityLevel level,
                                      const std::vector<uint8_t>& raw) {
  if (raw.empty() || IsOurs(raw)) return {};
  auto wrapped = teesim::hwblob::Wrap(static_cast<uint8_t>(level), raw);
  return wrapped ? std::move(*wrapped) : std::vector<uint8_t>{};
}

ndk::ScopedAStatus HardwareBlobForDomain(const char* what,
                                         const HardwareBackendDomain& domain,
                                         const std::vector<uint8_t>& blob,
                                         std::vector<uint8_t>* raw,
                                         bool* had_envelope = nullptr) {
  const auto result = teesim::hwblob::UnwrapForOwner(
      blob, static_cast<uint8_t>(domain.level), raw);
  if (had_envelope) *had_envelope = result != teesim::hwblob::UnwrapResult::kRaw;

  switch (result) {
    case teesim::hwblob::UnwrapResult::kRaw:
      return ndk::ScopedAStatus::ok();
    case teesim::hwblob::UnwrapResult::kMalformed:
      LOGE("%s: malformed TES hardware-blob envelope (blob=%s len=%zu)", what,
           BlobTag(blob).c_str(), blob.size());
      return Status(static_cast<int32_t>(ErrorCode::INVALID_KEY_BLOB));
    case teesim::hwblob::UnwrapResult::kOwnerMismatch: {
      const auto parsed = teesim::hwblob::Parse(blob);
      const auto owner = static_cast<SecurityLevel>(parsed.owner);
      LOGE("%s: hardware blob is persistently owned by %s but request arrived on %s#%llu",
           what, LevelName(owner), domain.Label(),
           static_cast<unsigned long long>(domain.epoch));
      return Status(static_cast<int32_t>(ErrorCode::INVALID_KEY_BLOB));
    }
    case teesim::hwblob::UnwrapResult::kUnwrapped:
      break;
  }

  if (IsOurs(*raw)) {
    LOGE("%s: hardware envelope contains a TES software-TA blob; refusing level laundering", what);
    return Status(static_cast<int32_t>(ErrorCode::INVALID_KEY_BLOB));
  }
  return ndk::ScopedAStatus::ok();
}

// KeyMint treats AttestationKey.keyBlob as an opaque hardware blob too. A hardware ATTEST_KEY that
// TES returned earlier may therefore come back wrapped in our persistent owner envelope. Strip only
// that outer metadata before forwarding to the genuine HAL. Raw RKP/legacy blobs and TES software
// blobs pass through unchanged; later routing logic still decides whether they are usable.
ndk::ScopedAStatus AttestationKeyForDomain(
    const char* what, const HardwareBackendDomain& domain,
    const std::optional<AttestationKey>& input,
    std::optional<AttestationKey>* output) {
  *output = input;
  if (!input) return ndk::ScopedAStatus::ok();

  std::vector<uint8_t> raw;
  bool enveloped = false;
  auto st = HardwareBlobForDomain(what, domain, input->keyBlob, &raw, &enveloped);
  if (!st.isOk()) return st;
  if (enveloped) {
    output->value().keyBlob = std::move(raw);
    LOGD("%s: unwrapped persisted %s ATTEST_KEY owner before real HAL",
         what, LevelName(domain.level));
  }
  return ndk::ScopedAStatus::ok();
}

struct HardwareBlobBinding {
  SecurityLevel level = SecurityLevel::SOFTWARE;
  std::string keymint_service;
  uint64_t last_verified_epoch = 0;
};

std::mutex g_hardware_blob_mu;
std::map<std::string, HardwareBlobBinding> g_hardware_blob_bindings;

void RememberHardwareBlob(const HardwareBackendDomain& domain,
                          const std::vector<uint8_t>& blob) {
  if (blob.empty()) return;
  const std::string tag = BlobTag(blob);
  std::lock_guard<std::mutex> lk(g_hardware_blob_mu);
  auto& binding = g_hardware_blob_bindings[tag];
  binding.level = domain.level;
  binding.keymint_service = domain.keymint_service;
  binding.last_verified_epoch = domain.epoch;
}

void ForgetHardwareBlob(const std::vector<uint8_t>& blob) {
  if (blob.empty()) return;
  std::lock_guard<std::mutex> lk(g_hardware_blob_mu);
  g_hardware_blob_bindings.erase(BlobTag(blob));
}

std::optional<HardwareBlobBinding> HardwareBlobBindingFor(
    const std::vector<uint8_t>& blob) {
  if (blob.empty()) return std::nullopt;
  std::lock_guard<std::mutex> lk(g_hardware_blob_mu);
  auto it = g_hardware_blob_bindings.find(BlobTag(blob));
  if (it == g_hardware_blob_bindings.end()) return std::nullopt;
  return it->second;
}

// A remembered binding is evidence, not the key's source of truth: the opaque hardware blob remains
// authoritative to the HAL. Reject only a known cross-domain use. A backend epoch change is expected
// after keystore2/HAL restart and is revalidated by the real HAL on the next successful operation.
ndk::ScopedAStatus ValidateKnownHardwareBlobDomain(const char* what,
                                                   const HardwareBackendDomain& domain,
                                                   const std::vector<uint8_t>& blob) {
  auto binding = HardwareBlobBindingFor(blob);
  if (!binding) return ndk::ScopedAStatus::ok();

  if (binding->level != domain.level) {
    LOGE("%s: hardware blob %s is bound to %s but request arrived on %s#%llu",
         what, BlobTag(blob).c_str(), LevelName(binding->level), domain.Label(),
         static_cast<unsigned long long>(domain.epoch));
    return Status(static_cast<int32_t>(ErrorCode::INVALID_KEY_BLOB));
  }

  if (!binding->keymint_service.empty() && !domain.keymint_service.empty() &&
      binding->keymint_service != domain.keymint_service) {
    LOGE("%s: hardware blob %s is bound to service %s but request arrived on %s",
         what, BlobTag(blob).c_str(), binding->keymint_service.c_str(),
         domain.keymint_service.c_str());
    return Status(static_cast<int32_t>(ErrorCode::INVALID_KEY_BLOB));
  }

  if (binding->last_verified_epoch != domain.epoch) {
    LOGD("%s: hardware blob %s crossing backend epoch %llu -> %llu on %s; allowing the real HAL "
         "to revalidate persistent blob ownership",
         what, BlobTag(blob).c_str(),
         static_cast<unsigned long long>(binding->last_verified_epoch),
         static_cast<unsigned long long>(domain.epoch), domain.Label());
  }
  return ndk::ScopedAStatus::ok();
}


struct TrustServiceProbeState {
  bool shared_secret_ok = false;
  bool secure_clock_ok = false;
  uint64_t last_probe_ms = 0;
};

std::mutex g_trust_probe_mu;
std::map<uint64_t, TrustServiceProbeState> g_trust_probe_state;

// Read-only health evidence for the real security domain used by strict hardware mode.
//
// IMPORTANT: do NOT call ISharedSecret::computeSharedSecret here. Android performs that N-party
// negotiation during boot with the complete, lexicographically sorted participant list. Re-running
// it with a partial list could change a participant's per-boot HMAC key and break HAT verification.
// getSharedSecretParameters() is the side-effect-free phase-1 query and is safe to repeat.
//
// ISecureClock::generateTimeStamp() is also safe for a diagnostic challenge: the returned token is
// never fed back into a KeyMint operation; we only verify that the genuine service can produce a
// structurally valid, MACed token. SecureClock is optional when the security environment already has
// an aligned secure time source, so absence is evidence, not a hard failure.
void MaybeProbeHardwareTrustServices(const HardwareBackendDomain& domain) {
  if (domain.dead.load(std::memory_order_acquire)) return;
  const SecurityLevel level = domain.level;
  if (level != SecurityLevel::TRUSTED_ENVIRONMENT && level != SecurityLevel::STRONGBOX) return;

  constexpr uint64_t kRetryMs = 5000;
  const uint64_t key = domain.epoch;
  const uint64_t now = NowMonoMs();
  {
    std::lock_guard<std::mutex> lk(g_trust_probe_mu);
    const auto it = g_trust_probe_state.find(key);
    if (it != g_trust_probe_state.end()) {
      const auto& state = it->second;
      if (state.shared_secret_ok && state.secure_clock_ok) return;
      if (state.last_probe_ms != 0 && now - state.last_probe_ms < kRetryMs) return;
    }
    g_trust_probe_state[key].last_probe_ms = now;
  }

  bool shared_ok = false;
  bool clock_ok = false;
  bool shared_present = false;
  bool clock_present = false;
  size_t seed_len = 0;
  size_t nonce_len = 0;
  size_t clock_mac_len = 0;
  int64_t clock_ms = 0;

  if (domain.shared_secret) {
    shared_present = true;
    sharedsecret::SharedSecretParameters params;
    auto st = domain.shared_secret->getSharedSecretParameters(&params);
    if (st.isOk()) {
      seed_len = params.seed.size();
      nonce_len = params.nonce.size();
      // AOSP permits an empty persistent seed, but nonce is the per-boot contribution and must be
      // present for a meaningful participant. Do not log either value; they are security protocol
      // material even though the interface exposes them to the negotiator.
      shared_ok = !params.nonce.empty();
    } else {
      LOGW("trust-services: %s#%llu bound SharedSecret failed: exception=%d service=%d",
           LevelName(level), static_cast<unsigned long long>(domain.epoch),
           st.getExceptionCode(), st.getServiceSpecificError());
    }
  } else if (domain.shared_secret_declared) {
    // Declared-but-unbound usually means a lazy service that Android has not started yet. Do not
    // start it from TES just to probe; the actual KeyMint operation remains authoritative.
    LOGD("trust-services: %s#%llu SharedSecret declared but not bound without starting lazy service",
         LevelName(level), static_cast<unsigned long long>(domain.epoch));
  }

  if (domain.secure_clock) {
    clock_present = true;
    // Diagnostic-only freshness value. This token is never trusted or consumed by TES/KeyMint.
    const int64_t challenge =
        static_cast<int64_t>((NowMonoMs() << 16) ^ static_cast<uint64_t>(getpid()) ^
                             domain.epoch);
    secureclock::TimeStampToken token;
    auto st = domain.secure_clock->generateTimeStamp(challenge, &token);
    if (st.isOk()) {
      clock_mac_len = token.mac.size();
      clock_ms = token.timestamp.milliSeconds;
      clock_ok = token.challenge == challenge && token.mac.size() == 32 && clock_ms >= 0;
    } else {
      LOGW("trust-services: SecureClock bound to %s#%llu failed: exception=%d service=%d",
           LevelName(level), static_cast<unsigned long long>(domain.epoch),
           st.getExceptionCode(), st.getServiceSpecificError());
    }
  } else if (domain.secure_clock_declared) {
    LOGD("trust-services: %s#%llu SecureClock declared but not bound without starting lazy service",
         LevelName(level), static_cast<unsigned long long>(domain.epoch));
  }

  {
    std::lock_guard<std::mutex> lk(g_trust_probe_mu);
    auto& state = g_trust_probe_state[key];
    state.shared_secret_ok = state.shared_secret_ok || shared_ok;
    state.secure_clock_ok = state.secure_clock_ok || clock_ok;
  }

  LOGI("trust-services: domain=%s#%llu keymint=%s sharedsecret=%s%s(declared=%d seed=%zu "
       "nonce=%zu) secureclock=%s%s(declared=%d mac=%zu time_ms=%lld) rkp=%s(declared=%d); "
       "TES did not participate in shared-secret negotiation",
       LevelName(level), static_cast<unsigned long long>(domain.epoch),
       domain.keymint_service.empty() ? "<compat/unknown>" : domain.keymint_service.c_str(),
       shared_present ? "" : "absent",
       shared_present ? (shared_ok ? "ok" : "bad") : "",
       domain.shared_secret_declared ? 1 : 0, seed_len, nonce_len,
       clock_present ? "" : "absent",
       clock_present ? (clock_ok ? "ok" : "bad") : "",
       domain.secure_clock_declared ? 1 : 0, clock_mac_len, static_cast<long long>(clock_ms),
       domain.rkp_instance.empty() ? "<none>" : domain.rkp_instance.c_str(),
       domain.rkp_declared ? 1 : 0);
}

bool HasSecurityLevel(const KeyCreationResult& result, SecurityLevel expected) {
  for (const auto& chars : result.keyCharacteristics) {
    if (chars.securityLevel == expected) return true;
  }
  return false;
}

// Strict hardware mode is defined by ownership, not by a label: the returned blob must not be one
// of our software-TA blobs and the HAL must report authorizations at the exact level whose binder
// handled the request. A mismatch is a backend failure, never a reason to silently simulate.
ndk::ScopedAStatus ValidateStrictHardwareResult(const char* what,
                                                const HardwareBackendDomain& domain,
                                                KeyCreationResult& result) {
  auto ready = RequireBackendLifecycleSynced(what, domain);
  if (!ready.isOk()) return ready;
  const SecurityLevel expected = domain.level;
  if (IsOurs(result.keyBlob)) {
    LOGE("%s: strict hardware invariant violated: real %s path returned a TES software blob",
         what, LevelName(expected));
    return Status(-1000);  // KeyMint UNKNOWN_ERROR
  }
  if (!HasSecurityLevel(result, expected)) {
    LOGE("%s: strict hardware invariant violated: result lacks %s KeyCharacteristics "
         "(blob=%s len=%zu)",
         what, LevelName(expected), BlobTag(result.keyBlob).c_str(), result.keyBlob.size());
    return Status(-1000);  // KeyMint UNKNOWN_ERROR
  }

  // For an actually attested key, require the certificate itself to agree with both the binder
  // identity and KeyCharacteristics. This catches a vendor path that returns a real key blob but
  // quietly attests it at TEE while the request arrived through /strongbox (or vice versa).
  //
  // A valid self-signed/unattested certificate may legitimately have no KeyDescription. The Rust
  // parser returns 1 for that case; malformed DER/KeyDescription remains a hard failure.
  if (!result.certificateChain.empty()) {
    const auto& leaf = result.certificateChain.front().encodedCertificate;
    int32_t attest_level = -1;
    int32_t keymint_level = -1;
    const int32_t rc = teesim_km_attestation_security_levels(
        leaf.data(), leaf.size(), &attest_level, &keymint_level);
    if (rc < 0) {
      LOGE("%s: strict hardware invariant violated: cannot parse attestation provenance rc=%d(%s) "
           "(blob=%s)",
           what, rc, teesim_km_err_name(rc), BlobTag(result.keyBlob).c_str());
      return Status(-1000);
    }
    if (rc == 0) {
      const int32_t want = static_cast<int32_t>(expected);
      if (attest_level != want || keymint_level != want) {
        LOGE("%s: strict hardware invariant violated: certificate levels attest=%d keymint=%d, "
             "expected %s(%d) (blob=%s)",
             what, attest_level, keymint_level, LevelName(expected), want,
             BlobTag(result.keyBlob).c_str());
        return Status(-1000);
      }
      LOGD("%s: attestation provenance confirms %s on both security-level axes",
           what, LevelName(expected));
    } else {
      LOGD("%s: certificate has no KeyDescription; relying on real blob + %s KeyCharacteristics",
           what, LevelName(expected));
    }
  }

  // Persist the owner only after every hardware/provenance check passes. The inner bytes stay
  // exactly what the genuine HAL returned; the outer TES header is routing metadata so the owner
  // survives keystore2/TES restart.
  const std::string raw_tag = BlobTag(result.keyBlob);
  auto enveloped = WrapHardwareBlob(expected, result.keyBlob);
  if (enveloped.empty()) {
    LOGE("%s: strict hardware invariant violated: could not envelope validated %s blob=%s len=%zu",
         what, LevelName(expected), raw_tag.c_str(), result.keyBlob.size());
    return Status(-1000);
  }
  result.keyBlob = std::move(enveloped);
  RememberHardwareBlob(domain, result.keyBlob);
  LOGD("%s: persisted %s hardware owner raw=%s envelope=%s len=%zu",
       what, LevelName(expected), raw_tag.c_str(), BlobTag(result.keyBlob).c_str(),
       result.keyBlob.size());

  // The key has proven it belongs to the genuine requested security level. Collect read-only
  // evidence that the surrounding HAT/time trust services are alive; never alter their negotiation.
  MaybeProbeHardwareTrustServices(domain);
  return ndk::ScopedAStatus::ok();
}

// True when the request creates an asymmetric key (RSA or EC) — the only algorithms KeyMint
// attests, and the only kind worth simulating. A symmetric key (AES/3DES/HMAC) is never attested,
// so simulating one would move the app's key off the real hardware for no gain, and an auth-bound
// one would then verify against a TA holding no device HMAC key. Those are forwarded to the real
// HAL, exactly as the keystore1 path does (#291). A request with no algorithm tag cannot be one of
// ours, so it forwards too.
bool IsAsymmetricKeyRequest(const std::vector<KeyParameter>& params) {
  for (const auto& p : params) {
    if (p.tag == Tag::ALGORITHM && p.value.getTag() == KeyParameterValue::algorithm) {
      const Algorithm a = p.value.get<KeyParameterValue::algorithm>();
      return a == Algorithm::RSA || a == Algorithm::EC;
    }
  }
  return false;
}

// STORAGE_KEY is not an attestation feature and must remain owned by the real KeyMint instance.
// Its long-lived blob is later passed to convertStorageKeyToEphemeral(), whose per-boot wrapping
// semantics belong to the hardware-backed device. Keep this explicit instead of relying on the
// broader "symmetric keys forward" rule so a future routing change can never accidentally pull
// storage keys into the simulation TA.
bool IsStorageKeyRequest(const std::vector<KeyParameter>& params) {
  for (const auto& p : params) {
    if (p.tag == Tag::STORAGE_KEY) return true;
  }
  return false;
}

// Hardware-authenticated and restart-sensitive secure-state authorizations cannot be faithfully
// enforced by our in-process TA. Real Gatekeeper/biometric HATs are signed with a per-boot device
// HMAC negotiated between the authenticators and genuine KeyMint; our isolated reference TA does
// not participate in that negotiation. Counter/timer/boot-state restrictions are also unsafe here:
// keystore2 can restart without rebooting Android, which recreates this TA and would reset state
// that KeyMint defines across the whole boot. Keep those keys in real hardware and, where possible,
// patch only their attestation certificate.
bool RequiresRealHardwareState(const std::vector<KeyParameter>& params) {
  // Tag 301 (BLOB_USAGE_REQUIREMENTS) existed in older KeyMint AIDL revisions but is reserved in
  // the Android 17 interface this project builds against, so the generated Tag enum no longer
  // names it. Keep recognizing its stable wire value for backlevel/compat implementations without
  // referring to a symbol that does not exist in newer generated headers.
  constexpr uint32_t kLegacyBlobUsageRequirementsTag = (1u << 28) | 301u;

  for (const auto& p : params) {
    if (static_cast<uint32_t>(p.tag) == kLegacyBlobUsageRequirementsTag) return true;
    switch (p.tag) {
      // Authentication and live device state.
      case Tag::USER_SECURE_ID:
      case Tag::UNLOCKED_DEVICE_REQUIRED:
      case Tag::TRUSTED_USER_PRESENCE_REQUIRED:
      case Tag::TRUSTED_CONFIRMATION_REQUIRED:
      case Tag::ALLOW_WHILE_ON_BODY:

      // Secure-world persistence / boot-lifetime state. The reference TA is configured with
      // sdd_mgr=None, and its process-local counters/latches cannot survive a keystore2 restart.
      case Tag::ROLLBACK_RESISTANCE:
      case Tag::EARLY_BOOT_ONLY:
      case Tag::MIN_SECONDS_BETWEEN_OPS:
      case Tag::MAX_USES_PER_BOOT:
      case Tag::USAGE_COUNT_LIMIT:
      case Tag::MAX_BOOT_LEVEL:
      case Tag::BOOTLOADER_ONLY:
        return true;
      default:
        break;
    }
  }
  return false;
}

// True if the request creates a key with ATTEST_KEY purpose (an attestation key). Such a key MUST be
// minted in the TA (generation), never patched: only if we hold its private key can our TA later sign
// — and root-of-trust-patch — the leaves this key attests. A patched real-hardware attest key can only
// ever produce a real, unlocked delegated leaf (we cannot re-sign under a key we don't hold).
bool IsAttestKeyRequest(const std::vector<KeyParameter>& params) {
  for (const auto& p : params) {
    if (p.tag == Tag::PURPOSE && p.value.getTag() == KeyParameterValue::keyPurpose &&
        p.value.get<KeyParameterValue::keyPurpose>() == KeyPurpose::ATTEST_KEY) {
      return true;
    }
  }
  return false;
}

// --- auth / timestamp token marshalling --------------------------------------

// Flatten an optional AIDL HardwareAuthToken into the flat C ABI struct. Returns a pointer to
// `storage` (filled in) when the token is present, or nullptr when absent — exactly the nullability
// the TA expects. The mac pointer borrows the token's vector, which outlives the FFI call.
const TsAuthToken* FlattenAuth(const std::optional<HardwareAuthToken>& tok, TsAuthToken* storage) {
  if (!tok) return nullptr;
  storage->challenge = tok->challenge;
  storage->user_id = tok->userId;
  storage->authenticator_id = tok->authenticatorId;
  storage->authenticator_type = static_cast<int32_t>(tok->authenticatorType);
  storage->timestamp_ms = tok->timestamp.milliSeconds;
  storage->mac = tok->mac.empty() ? nullptr : tok->mac.data();
  storage->mac_len = tok->mac.size();
  return storage;
}

// Flatten an optional secureclock TimeStampToken into the flat C ABI struct (nullptr when absent).
const TsTimestampToken* FlattenTimestamp(const std::optional<secureclock::TimeStampToken>& tok,
                                         TsTimestampToken* storage) {
  if (!tok) return nullptr;
  storage->challenge = tok->challenge;
  storage->timestamp_ms = tok->timestamp.milliSeconds;
  storage->mac = tok->mac.empty() ? nullptr : tok->mac.data();
  storage->mac_len = tok->mac.size();
  return storage;
}

// --- Operation tracing -------------------------------------------------------
//
// A capture that records only blob_len cannot answer the question these failures
// pose: whether a decrypt that fails its tag is being asked to decrypt ciphertext
// that belongs to a different key, or whether the operation itself was mishandled.
// Length is not identity -- two keys of the same size are indistinguishable, and a
// blob that changed under an upgrade keeps its length. So tag every blob, and
// record what an AEAD verdict actually depends on: the nonce, the tag length, and
// the byte counts on the way through.

// 64-bit FNV-1a over the blob, printed as 16 hex digits. A digest, not the bytes:
// enough to say "the same blob as before" or "a different one", and no key material
// reaches the log.
std::string BlobTag(const std::vector<uint8_t>& blob) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (uint8_t b : blob) {
    h ^= b;
    h *= 0x100000001b3ULL;
  }
  char buf[17];
  snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(h));
  return std::string(buf);
}

std::string HexOf(const std::vector<uint8_t>& v) {
  static const char* kHex = "0123456789abcdef";
  std::string out;
  out.reserve(v.size() * 2);
  for (uint8_t b : v) {
    out.push_back(kHex[b >> 4]);
    out.push_back(kHex[b & 0xf]);
  }
  return out;
}

// The begin parameters an AEAD or RSA verdict turns on. A wrong nonce and stale
// ciphertext both surface as VERIFICATION_FAILED, and nothing in the old capture
// told them apart.
// The shape of a key being created: algorithm, size or curve, and purposes, by name. The parameter
// count alone cannot tell an attested EC signing key from an AES key an app keeps a secret under.
std::string KeyShape(const std::vector<KeyParameter>& params) {
  std::string algorithm = "?", size, curve, purposes;
  for (const auto& p : params) {
    if (p.tag == Tag::ALGORITHM && p.value.getTag() == KeyParameterValue::algorithm) {
      algorithm = toString(p.value.get<KeyParameterValue::algorithm>());
    } else if (p.tag == Tag::KEY_SIZE && p.value.getTag() == KeyParameterValue::integer) {
      size = std::to_string(p.value.get<KeyParameterValue::integer>());
    } else if (p.tag == Tag::EC_CURVE && p.value.getTag() == KeyParameterValue::ecCurve) {
      curve = toString(p.value.get<KeyParameterValue::ecCurve>());
    } else if (p.tag == Tag::PURPOSE && p.value.getTag() == KeyParameterValue::keyPurpose) {
      if (!purposes.empty()) purposes += "|";
      purposes += toString(p.value.get<KeyParameterValue::keyPurpose>());
    }
  }
  std::string out = algorithm;
  if (!curve.empty()) {
    out += "/" + curve;
  } else if (!size.empty()) {
    out += "-" + size;
  }
  return out + " purpose=" + (purposes.empty() ? "-" : purposes);
}

// The full parameter list of a request, decoded (see KmDescribeParams).
std::string ParamsDesc(const std::vector<KeyParameter>& params) {
  const auto km = ToKmVec(params);
  return KmDescribeParams(km.data(), km.size());
}

// A short id naming ONE operation, not the key it runs on. Two concurrent operations on the same
// blob are otherwise indistinguishable, which is exactly the case a failing AEAD tag poses: the
// question is whether this decrypt was handed the nonce belonging to its own ciphertext, and with
// only op[<blob>] to go on, the begin that carried that nonce cannot be identified. Our own
// operations print the TA's real handle, so a line here and a line from the TA name the same thing;
// a forwarded one has no handle we can see, so it gets a process-local serial.
std::string OpId(int64_t op_handle) {
  char buf[24];
  snprintf(buf, sizeof(buf), "h%llx", static_cast<unsigned long long>(op_handle));
  return std::string(buf);
}

std::string NextForwardedOpId() {
  static std::atomic<uint32_t> next{0};
  char buf[16];
  snprintf(buf, sizeof(buf), "f%x", next.fetch_add(1, std::memory_order_relaxed));
  return std::string(buf);
}

// --- IKeyMintOperation -------------------------------------------------------

class TeesimKeyMintOperation : public BnKeyMintOperation {
 public:
  // `ctx` is the caller tag captured at begin(): keystore2 drives update/finish/abort on whatever
  // binder thread the app's later calls land on, and getCallingUid there is the app's, but an
  // operation outliving its begin is exactly where an anonymous line would leave us guessing. Carry
  // it with the operation instead of re-deriving it.
  TeesimKeyMintOperation(TaPtr ta, int64_t op_handle, std::string blob_tag, std::string ctx,
                         bool owns_strongbox_slot, TsDelayRange ta_call_delay)
      : ta_(std::move(ta)),
        op_handle_(op_handle),
        op_id_(OpId(op_handle)),
        blob_tag_(std::move(blob_tag)),
        ctx_(std::move(ctx)),
        owns_strongbox_slot_(owns_strongbox_slot),
        ta_call_delay_(ta_call_delay) {}
  ~TeesimKeyMintOperation() override {
    LogContext lc_(ctx_);
    // An operation destroyed without a finish or an abort is keystore2 dropping it — a pruned
    // operation slot, or an app that went away mid-decrypt. Logged so the operation's end is
    // visible, as its forwarded twin's abort is.
    if (!finished_) {
      int32_t rc = teesim_km_abort(ta_.get(), op_handle_);
      LOGD("op[%s/%s] ours dropped without finish: abandoned by keystore2, aborted in the TA rc=%d(%s)",
           blob_tag_.c_str(), op_id_.c_str(), rc, teesim_km_err_name(rc));
    }
    ReleaseStrongBoxSlot();
  }

  ndk::ScopedAStatus updateAad(const std::vector<uint8_t>& input,
                               const std::optional<HardwareAuthToken>& authToken,
                               const std::optional<secureclock::TimeStampToken>& tst) override {
    LogContext lc_(ctx_);
    TsAuthToken at;
    TsTimestampToken tt;
    ApplyTimingDelay(ta_call_delay_, "ta-call", "");
    int32_t rc = teesim_km_update_aad(ta_.get(), op_handle_, input.data(), input.size(),
                                      FlattenAuth(authToken, &at), FlattenTimestamp(tst, &tt));
    LogOp("ours update_aad", rc, "aad=%zu", input.size());
    return Status(rc);
  }

  ndk::ScopedAStatus update(const std::vector<uint8_t>& input,
                            const std::optional<HardwareAuthToken>& authToken,
                            const std::optional<secureclock::TimeStampToken>& tst,
                            std::vector<uint8_t>* out) override {
    LogContext lc_(ctx_);
    TsAuthToken at;
    TsTimestampToken tt;
    uint8_t* buf = nullptr;
    size_t len = 0;
    ApplyTimingDelay(ta_call_delay_, "ta-call", "");
    int32_t rc = teesim_km_update(ta_.get(), op_handle_, input.data(), input.size(),
                                  FlattenAuth(authToken, &at), FlattenTimestamp(tst, &tt), &buf, &len);
    in_total_ += input.size();
    LogOp("ours update", rc, "in=%zu out=%zu in_total=%zu", input.size(), len, in_total_);
    if (rc != 0) return Status(rc);
    out->assign(buf, buf + len);
    teesim_km_free_buf(buf, len);
    return ndk::ScopedAStatus::ok();
  }

  ndk::ScopedAStatus finish(const std::optional<std::vector<uint8_t>>& input,
                            const std::optional<std::vector<uint8_t>>& signature,
                            const std::optional<HardwareAuthToken>& authToken,
                            const std::optional<secureclock::TimeStampToken>& tst,
                            const std::optional<std::vector<uint8_t>>& confirmationToken,
                            std::vector<uint8_t>* out) override {
    LogContext lc_(ctx_);
    const uint8_t* in_ptr = input ? input->data() : nullptr;
    size_t in_len = input ? input->size() : 0;
    const uint8_t* sig_ptr = signature ? signature->data() : nullptr;
    size_t sig_len = signature ? signature->size() : 0;
    const uint8_t* conf_ptr = confirmationToken ? confirmationToken->data() : nullptr;
    size_t conf_len = confirmationToken ? confirmationToken->size() : 0;
    TsAuthToken at;
    TsTimestampToken tt;
    uint8_t* buf = nullptr;
    size_t len = 0;
    ApplyTimingDelay(ta_call_delay_, "ta-call", "");
    int32_t rc = teesim_km_finish(ta_.get(), op_handle_, in_ptr, in_len, sig_ptr, sig_len,
                                  FlattenAuth(authToken, &at), FlattenTimestamp(tst, &tt), conf_ptr,
                                  conf_len, &buf, &len);
    finished_ = true;
    ReleaseStrongBoxSlot();
    // in_total is what the tag check actually consumed: for GCM the reference TA
    // holds the trailing tag back from update() and verifies it here, so a finish
    // with no input is normal and the interesting number is everything before it.
    LogOp("ours finish", rc, "in=%zu sig=%zu in_total=%zu out=%zu", in_len, sig_len,
          in_total_ + in_len, len);
    if (rc != 0) return Status(rc);
    out->assign(buf, buf + len);
    teesim_km_free_buf(buf, len);
    return ndk::ScopedAStatus::ok();
  }

  ndk::ScopedAStatus abort() override {
    LogContext lc_(ctx_);
    finished_ = true;
    ApplyTimingDelay(ta_call_delay_, "ta-call", "");
    int32_t rc = teesim_km_abort(ta_.get(), op_handle_);
    ReleaseStrongBoxSlot();
    LogOp("ours abort", rc, "in_total=%zu", in_total_);
    return Status(rc);
  }

 private:
  void ReleaseStrongBoxSlot() {
    if (!owns_strongbox_slot_) return;
    owns_strongbox_slot_ = false;
    ReleaseStrongBoxOperation();
  }

  // One line per call, at the level the outcome earns: a non-zero rc is a failure the app sees, so it
  // logs at WARN while successes stay at DEBUG. The error is named rather than left as a bare number.
  __attribute__((format(printf, 4, 5)))
  void LogOp(const char* what, int32_t rc, const char* fmt, ...) {
    char detail[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(detail, sizeof(detail), fmt, ap);
    va_end(ap);
    if (rc == 0) {
      LOGD("op[%s/%s] %s: %s rc=0", blob_tag_.c_str(), op_id_.c_str(), what, detail);
    } else {
      LOGW("op[%s/%s] %s FAILED: rc=%d(%s) %s", blob_tag_.c_str(), op_id_.c_str(), what, rc,
           teesim_km_err_name(rc), detail);
    }
  }

  TaPtr ta_;
  int64_t op_handle_;
  std::string op_id_;
  std::string blob_tag_;
  std::string ctx_;
  size_t in_total_ = 0;
  bool finished_ = false;
  bool owns_strongbox_slot_ = false;
  TsDelayRange ta_call_delay_{};
};

// --- IKeyMintOperation, forwarded --------------------------------------------
//
// A forwarded begin used to hand keystore2 the real HAL's operation object, after
// which update/finish went straight there and nothing about them was observable
// here. That is precisely the case that needs watching -- a non-target app whose
// decrypt fails its tag in the real TA -- so wrap the operation and delegate. Every
// call is passed through untouched; only the counts are recorded.
class ForwardedKeyMintOperation : public BnKeyMintOperation {
 public:
  ForwardedKeyMintOperation(std::shared_ptr<IKeyMintOperation> real, std::string blob_tag,
                            std::string op_id, std::string ctx,
                            std::shared_ptr<HardwareBackendDomain> domain)
      : real_(std::move(real)),
        blob_tag_(std::move(blob_tag)),
        op_id_(std::move(op_id)),
        ctx_(std::move(ctx)),
        domain_(std::move(domain)) {}

  ndk::ScopedAStatus updateAad(const std::vector<uint8_t>& input,
                               const std::optional<HardwareAuthToken>& authToken,
                               const std::optional<secureclock::TimeStampToken>& tst) override {
    LogContext lc_(ctx_);
    LogDeadDomainIfNeeded("updateAad");
    ForwardGuard g;
    auto st = real_->updateAad(input, authToken, tst);
    LogOp("real update_aad", st, "aad=%zu", input.size());
    return st;
  }

  ndk::ScopedAStatus update(const std::vector<uint8_t>& input,
                            const std::optional<HardwareAuthToken>& authToken,
                            const std::optional<secureclock::TimeStampToken>& tst,
                            std::vector<uint8_t>* out) override {
    LogContext lc_(ctx_);
    LogDeadDomainIfNeeded("update");
    ForwardGuard g;
    auto st = real_->update(input, authToken, tst, out);
    in_total_ += input.size();
    LogOp("real update", st, "in=%zu out=%zu in_total=%zu", input.size(),
          out ? out->size() : 0, in_total_);
    return st;
  }

  ndk::ScopedAStatus finish(const std::optional<std::vector<uint8_t>>& input,
                            const std::optional<std::vector<uint8_t>>& signature,
                            const std::optional<HardwareAuthToken>& authToken,
                            const std::optional<secureclock::TimeStampToken>& tst,
                            const std::optional<std::vector<uint8_t>>& confirmationToken,
                            std::vector<uint8_t>* out) override {
    LogContext lc_(ctx_);
    LogDeadDomainIfNeeded("finish");
    ForwardGuard g;
    auto st = real_->finish(input, signature, authToken, tst, confirmationToken, out);
    const size_t in_len = input ? input->size() : 0;
    // from=real-hal is the fact that decides whether a failure here is ours: the module forwarded
    // the call untouched and the real hardware is what rejected it.
    LogOp("real finish", st, "in=%zu sig=%zu in_total=%zu out=%zu from=real-hal", in_len,
          signature ? signature->size() : 0, in_total_ + in_len, out ? out->size() : 0);
    return st;
  }

  ndk::ScopedAStatus abort() override {
    LogContext lc_(ctx_);
    LogDeadDomainIfNeeded("abort");
    ForwardGuard g;
    auto st = real_->abort();
    LogOp("real abort", st, "in_total=%zu", in_total_);
    return st;
  }

 private:
  void LogDeadDomainIfNeeded(const char* what) const {
    if (domain_ && domain_->dead.load(std::memory_order_acquire)) {
      LOGW("op[%s/%s %s#%llu] %s is using a backend epoch already marked dead",
           blob_tag_.c_str(), op_id_.c_str(), domain_->Label(),
           static_cast<unsigned long long>(domain_->epoch), what);
    }
  }

  // The forwarded twin of TeesimKeyMintOperation::LogOp: a real-hardware rejection logs at WARN with
  // its status named, so it never reads like a success.
  __attribute__((format(printf, 4, 5)))
  void LogOp(const char* what, const ndk::ScopedAStatus& st, const char* fmt, ...) {
    char detail[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(detail, sizeof(detail), fmt, ap);
    va_end(ap);
    if (st.isOk()) {
      LOGD("op[%s/%s %s#%llu] %s: %s rc=0", blob_tag_.c_str(), op_id_.c_str(),
           domain_ ? domain_->Label() : "?",
           domain_ ? static_cast<unsigned long long>(domain_->epoch) : 0ULL,
           what, detail);
    } else {
      LOGW("op[%s/%s %s#%llu] %s FAILED: %s %s", blob_tag_.c_str(), op_id_.c_str(),
           domain_ ? domain_->Label() : "?", domain_ ? static_cast<unsigned long long>(domain_->epoch) : 0ULL,
           what, StatusDesc(st).c_str(), detail);
    }
  }

  std::shared_ptr<IKeyMintOperation> real_;
  std::string blob_tag_;
  std::string op_id_;
  std::string ctx_;
  std::shared_ptr<HardwareBackendDomain> domain_;
  size_t in_total_ = 0;
};

// --- IKeyMintDevice ----------------------------------------------------------

class TeesimKeyMintDevice : public BnKeyMintDevice {
 public:
  explicit TeesimKeyMintDevice(std::shared_ptr<HardwareBackendDomain> domain)
      : domain_(std::move(domain)),
        level_(domain_ ? domain_->level : SecurityLevel::SOFTWARE),
        real_(domain_ ? domain_->keymint : nullptr) {}

  ndk::ScopedAStatus getHardwareInfo(KeyMintHardwareInfo* info) override {
    LogContext lc_(RequestCtx());
    if (!real_) {
      // A local TES proxy without a genuine backend is not TEE/StrongBox. Never manufacture a
      // hardware identity merely because this wrapper was constructed with a level hint.
      LOGE("getHardwareInfo: backend domain %s#%llu has no real KeyMint device; refusing fake "
           "hardware identity",
           domain_ ? domain_->Label() : "?",
           domain_ ? static_cast<unsigned long long>(domain_->epoch) : 0ULL);
      return NoRealHal(__func__);
    }
    ForwardGuard g;
    return real_->getHardwareInfo(info);
  }

  ndk::ScopedAStatus generateKey(const std::vector<KeyParameter>& keyParams,
                                 const std::optional<AttestationKey>& attestationKey,
                                 KeyCreationResult* out) override {
    LogContext lc_(RequestCtx());
    const uid_t caller_uid = AIBinder_getCallingUid();
    RecordUsage(static_cast<int32_t>(caller_uid));  // every app that asks for a key, for the daemon's usage view
    RequestTarget t = ProfileForRequest(keyParams, caller_uid, level_);
    const bool is_attestation_request =
        HasParamTag(keyParams, Tag::ATTESTATION_CHALLENGE) || attestationKey.has_value();
    if (t.ta && is_attestation_request)
      ApplyTimingDelay(t.timing.attestation, "attestation", t.id);
    std::optional<AttestationKey> hardware_attestation_key;
    auto attest_owner_status = AttestationKeyForDomain(
        "generateKey/attestationKey", *domain_, attestationKey, &hardware_attestation_key);
    if (!attest_owner_status.isOk()) return attest_owner_status;

    TsRkpVerdict rkp{};
    teesim_hook_take_rkp_verdict(&rkp);
    // A verdict recorded more than this long ago cannot belong to the request in hand: keystore2
    // resolves the attest key immediately before calling generateKey on the same thread. An older
    // one was armed for a request it then abandoned, and reporting it here would attribute another
    // app's gate decision to this key.
    constexpr uint32_t kRkpFreshMs = 2000;
    const bool rkp_none = std::strcmp(rkp.verdict, "none") == 0;
    const bool rkp_stale = !rkp_none && rkp.age_ms > kRkpFreshMs;
    // "none" has no uid, no rid and no age to report, and it is the common case — most requests
    // never reach the gate at all. Printing three placeholder fields for it would put noise on
    // every line to say nothing happened.
    char rkp_gate[96];
    if (rkp_none) {
      snprintf(rkp_gate, sizeof(rkp_gate), "none");
    } else {
      snprintf(rkp_gate, sizeof(rkp_gate), "%s(uid=%d,r%04x,%ums%s)", rkp.verdict, rkp.uid, rkp.rid,
               rkp.age_ms, rkp_stale ? ",STALE" : "");
    }
    // Only a target app's own call earns INFO: every OTHER app on the device calling generateKey
    // (the overwhelming majority of calls this router ever sees) is not our concern, and at INFO its
    // parameters would drown the target-app lines this exists for.
    if (t.ta) {
      LOGI("generateKey: level=%s, profile=%s, %s, caller_attest_key=%d, patch_mode=%d, "
           "hardware_mode=%d, strongbox_ok=%d, rkp_gate=%s",
           LevelName(level_), t.id.empty() ? "-" : t.id.c_str(), KeyShape(keyParams).c_str(),
           attestationKey.has_value(), t.patch_mode, t.hardware_mode, g_strongbox_ok, rkp_gate);
      LOGI("generateKey: params=%s", ParamsDesc(keyParams).c_str());
    } else {
      LOGD("generateKey: level=%s, %s, caller_attest_key=%d, not a target, rkp_gate=%s",
           LevelName(level_), KeyShape(keyParams).c_str(), attestationKey.has_value(), rkp_gate);
      LOGD("generateKey: params=%s", ParamsDesc(keyParams).c_str());
    }
    // An attest key decides everything that follows — a foreign one can only ever be forwarded, and
    // the leaf it signs keeps the real root of trust — so name it here, next to the gate verdict that
    // let it through. "rkp_gate=none" with an attest key present means keystore2 obtained it without
    // ever calling the getRegistration we hook: the key came from somewhere our gate cannot see.
    if (attestationKey) {
      const bool ours = IsOurs(attestationKey->keyBlob);
      LOGI("generateKey: attest key=%s, blob_len=%zu, ours=%d, issuer_len=%zu (%s)",
           BlobTag(attestationKey->keyBlob).c_str(), attestationKey->keyBlob.size(), ours,
           attestationKey->issuerSubjectName.size(),
           ours ? "ours: its leaves stay keybox-rooted"
                : "foreign: we hold no private half, so this leaf keeps the REAL root of trust");
    }
    if (!t.ta) {
      if (real_) {
        LOGD("generateKey: forwarding to real HAL (not a target)");
        ForwardGuard g;
        auto st = real_->generateKey(keyParams, hardware_attestation_key, out);
        if (!st.isOk()) LOGW("generateKey: FAILED in the real HAL: %s", StatusDesc(st).c_str());
        return st;
      }
      return NoRealHal(__func__);
    }
    // Storage keys have stricter ownership than ordinary symmetric keys: their persistent blob and
    // convertStorageKeyToEphemeral() lifecycle must stay on this exact real KeyMint security level.
    // Never fall back to our TA, even if routing rules for other key types change later.
    if (IsStorageKeyRequest(keyParams)) {
      if (real_) {
        LOGI("generateKey: STORAGE_KEY requested; forwarding to the real %s HAL (hardware-owned, "
             "no simulated fallback)", LevelName(level_));
        ForwardGuard g;
        auto st = real_->generateKey(keyParams, hardware_attestation_key, out);
        if (!st.isOk())
          LOGW("generateKey: STORAGE_KEY FAILED in the real HAL: %s", StatusDesc(st).c_str());
        if (t.hardware_mode && st.isOk()) {
          auto valid = ValidateStrictHardwareResult("generateKey/storage", *domain_, *out);
          if (!valid.isOk()) return valid;
        }
        return st;
      }
      LOGW("generateKey: STORAGE_KEY requested but no real HAL exists; refusing simulated fallback");
      return NoRealHal(__func__);
    }
    // Any key whose use depends on a real HAT or live secure-device state must remain hardware-owned.
    // For a normal target request with no foreign attest key we still patch the real leaf under the
    // profile keybox, but the private key and all authorization enforcement stay in the genuine HAL.
    if (RequiresRealHardwareState(keyParams)) {
      if (!real_) {
        LOGW("generateKey: auth/state-bound key requested but no real HAL exists; refusing simulated "
             "fallback");
        return NoRealHal(__func__);
      }
      if (attestationKey && !IsOurs(attestationKey->keyBlob)) {
        LOGI("generateKey: auth/state-bound key with foreign attest key; forwarding whole request to "
             "the real %s HAL", LevelName(level_));
        ForwardGuard g;
        auto st = real_->generateKey(keyParams, hardware_attestation_key, out);
        if (!st.isOk())
          LOGW("generateKey: auth/state-bound key FAILED in the real HAL: %s",
               StatusDesc(st).c_str());
        if (t.hardware_mode && st.isOk()) {
          auto valid = ValidateStrictHardwareResult("generateKey/auth", *domain_, *out);
          if (!valid.isOk()) return valid;
        }
        return st;
      }
      if (attestationKey && IsOurs(attestationKey->keyBlob)) {
        if (t.hardware_mode) {
          LOGW("generateKey: strict hardware auth/state-bound request references a legacy TES "
               "software ATTEST_KEY; refusing to break the delegated graph. Regenerate the parent "
               "ATTEST_KEY inside real %s first", LevelName(level_));
          return Status(static_cast<int32_t>(ErrorCode::INVALID_KEY_BLOB));
        }
        // Compatibility mode may still preserve the hardware business key while dropping a software
        // parent it cannot pass to the real HAL.
        LOGW("generateKey: auth/state-bound key names one of our attest keys; real HAL cannot access "
             "that private key, so preserving hardware auth semantics and patching under the profile "
             "keybox instead of simulating the key");
      } else {
        LOGI("generateKey: auth/state-bound key; keeping key/auth enforcement in the real %s HAL "
             "and patching attestation only", LevelName(level_));
      }
      return PatchAttest(t.ta.get(), keyParams, out, /*hardware_required=*/true);
    }

    // A target's ordinary symmetric key is forwarded, not simulated (see IsAsymmetricKeyRequest).
    // An attest key is always asymmetric, so this never diverts one.
    if (!IsAsymmetricKeyRequest(keyParams)) {
      if (real_) {
        LOGI("generateKey: symmetric key; forwarding to the real HAL (never attested, kept in the "
             "real TEE)");
        ForwardGuard g;
        auto st = real_->generateKey(keyParams, hardware_attestation_key, out);
        if (!st.isOk())
          LOGW("generateKey: FAILED in the real HAL (symmetric): %s", StatusDesc(st).c_str());
        if (t.hardware_mode && st.isOk()) {
          auto valid = ValidateStrictHardwareResult("generateKey/symmetric", *domain_, *out);
          if (!valid.isOk()) return valid;
        }
        return st;
      }
      return NoRealHal(__func__);
    }
    // Creating an ATTESTATION KEY (ATTEST_KEY purpose) always mints it in the TA (ours). Unless the
    // caller named one of our keys as its attest key (the "ours" case just below), we ignore any
    // injected attest key and self-attest the new key under the keybox. This MUST come before the
    // attestationKey branch below: on TrustedEnvironment, attesting a new attest key that carries a
    // challenge makes keystore2 inject an RKP-provisioned (real hardware) key — which that branch would
    // forward, leaving us a foreign attest key we can never re-root. We must hold this key's private key
    // so the leaves it later signs get a patched root of trust. (StrongBox has no RKP, so its attest-key
    // creation already arrived with no injected key — exactly why StrongBox worked and TE did not.)
    if (IsAttestKeyRequest(keyParams)) {
      // hardware mode means the ATTEST_KEY private half must live in the same genuine KeyMint level
      // as the keys it will later attest. AOSP explicitly models delegated attestation as a KeyMint
      // keyBlob with purpose ATTEST_KEY, so keeping this key in the software TA would defeat the point
      // of a hardware TEE/StrongBox backend.
      if (t.hardware_mode) {
        if (!real_) {
          LOGW("generateKey: hardware ATTEST_KEY requested at %s but no real HAL exists; refusing "
               "software fallback", LevelName(level_));
          return NoRealHal(__func__);
        }
        if (attestationKey && IsOurs(attestationKey->keyBlob)) {
          LOGW("generateKey: strict hardware ATTEST_KEY creation references a legacy TES software "
               "parent; refusing silent graph rewrite. The parent must be regenerated in real %s",
               LevelName(level_));
          return Status(static_cast<int32_t>(ErrorCode::INVALID_KEY_BLOB));
        } else if (attestationKey) {
          LOGI("generateKey: hardware ATTEST_KEY with hardware parent; forwarding delegated graph "
               "to real %s HAL", LevelName(level_));
          ForwardGuard g;
          auto st = real_->generateKey(keyParams, hardware_attestation_key, out);
          if (!st.isOk()) {
            LOGW("generateKey: hardware delegated ATTEST_KEY FAILED in real HAL: %s",
                 StatusDesc(st).c_str());
            return st;
          }
          auto valid = ValidateStrictHardwareResult("generateKey/attest-key-delegated", *domain_, *out);
          if (!valid.isOk()) return valid;
          return st;
        }
        LOGI("generateKey: strict hardware ATTEST_KEY -> real %s HAL, then keybox re-root only",
             LevelName(level_));
        return PatchAttest(t.ta.get(), keyParams, out, /*hardware_required=*/true);
      }

      // Compatibility modes retain the historical software-owned attest-key graph.
      if (attestationKey && IsOurs(attestationKey->keyBlob)) {
        LOGI("generateKey: attest-key creation attested by our attest key; signing its leaf with it (preserving the A->B chain)");
        return Simulate(t.ta.get(), keyParams, attestationKey, t.timing.ta_call, t.id, out);
      }
      LOGI("generateKey: attest-key creation -> forced generation in the TA (compatibility mode)");
      return Simulate(t.ta.get(), keyParams, std::nullopt, out);
    }
    // A leaf that carries an attest key: keystore2 appends that attest key's OWN stored certificate chain
    // to the leaf we return, so we emit ONLY the leaf, never extra certificates.
    if (attestationKey) {
      if (t.hardware_mode) {
        if (!real_) return NoRealHal(__func__);
        if (IsOurs(attestationKey->keyBlob)) {
          LOGW("generateKey: strict hardware delegated request references a legacy TES software "
               "ATTEST_KEY; refusing silent parent replacement. Regenerate the parent in real %s",
               LevelName(level_));
          return Status(static_cast<int32_t>(ErrorCode::INVALID_KEY_BLOB));
        }

        LOGI("generateKey: strict hardware delegated/RKP attest key -> real %s HAL",
             LevelName(level_));
        ForwardGuard g;
        auto st = real_->generateKey(keyParams, hardware_attestation_key, out);
        if (!st.isOk()) {
          LOGW("generateKey: strict hardware delegated generation FAILED: %s",
               StatusDesc(st).c_str());
          return st;
        }
        auto valid = ValidateStrictHardwareResult("generateKey/delegated", *domain_, *out);
        if (!valid.isOk()) return valid;
        return st;
      }

      if (IsOurs(attestationKey->keyBlob)) {
        // Compatibility generation mode: our attest key signs the leaf in the software TA.
        LOGI("generateKey: attest key is ours; signing the leaf with it (no extra certs)");
        return Simulate(t.ta.get(), keyParams, attestationKey, t.timing.ta_call, t.id, out);
      }
      LOGI("generateKey: foreign attest key (blob_len=%zu); forwarding to real HAL, no extra certs",
           attestationKey->keyBlob.size());
      if (!real_) {
        LOGW("generateKey: foreign attest key but no real HAL; failing");
        return NoRealHal(__func__);
      }
      ForwardGuard g;
      auto st = real_->generateKey(keyParams, hardware_attestation_key, out);
      if (!st.isOk()) {
        LOGW("generateKey: FAILED in the real HAL under a foreign attest key: %s",
             StatusDesc(st).c_str());
      }
      return st;
    }
    // No attest key. Patch mode re-roots the real hardware leaf under the keybox; a StrongBox that cannot
    // attest (g_strongbox_ok=false), or no real HAL, generates instead.
    if (t.hardware_mode) {
      if (!real_) {
        LOGW("generateKey: strict hardware mode has no real %s HAL; refusing software fallback",
             LevelName(level_));
        return NoRealHal(__func__);
      }
      LOGI("generateKey: strict hardware mode -> real %s HAL; TA may re-root only the certificate",
           LevelName(level_));
      return PatchAttest(t.ta.get(), keyParams, out, /*hardware_required=*/true);
    }
    if (t.patch_mode && real_ && (level_ != SecurityLevel::STRONGBOX || g_strongbox_ok)) {
      return PatchAttest(t.ta.get(), keyParams, out);
    }
    return Simulate(t.ta.get(), keyParams, attestationKey, t.timing.ta_call, t.id, out);
  }

  ndk::ScopedAStatus importKey(const std::vector<KeyParameter>& keyParams, KeyFormat keyFormat,
                               const std::vector<uint8_t>& keyData,
                               const std::optional<AttestationKey>& attestationKey,
                               KeyCreationResult* out) override {
    LogContext lc_(RequestCtx());
    RequestTarget t = ProfileForRequest(keyParams, AIBinder_getCallingUid(), level_);
    const bool is_attestation_request =
        HasParamTag(keyParams, Tag::ATTESTATION_CHALLENGE) || attestationKey.has_value();
    if (t.ta && is_attestation_request)
      ApplyTimingDelay(t.timing.attestation, "attestation", t.id);
    std::optional<AttestationKey> hardware_attestation_key;
    auto attest_owner_status = AttestationKeyForDomain(
        "importKey/attestationKey", *domain_, attestationKey, &hardware_attestation_key);
    if (!attest_owner_status.isOk()) return attest_owner_status;
    TaPtr ta = t.ta;
    // importKey creates a key exactly as generateKey does, so it is logged the same way: only a
    // target's own call earns INFO; every other app importing a key of its own is not our concern.
    if (ta) {
      LOGI("importKey: level=%s, profile=%s, %s, format=%s, key_data_len=%zu, "
           "caller_attest_key=%d, patch_mode=%d, hardware_mode=%d",
           LevelName(level_), t.id.empty() ? "-" : t.id.c_str(), KeyShape(keyParams).c_str(),
           toString(keyFormat).c_str(), keyData.size(), attestationKey.has_value(),
           t.patch_mode, t.hardware_mode);
      LOGI("importKey: params=%s", ParamsDesc(keyParams).c_str());
    } else {
      LOGD("importKey: level=%s, %s, format=%s, key_data_len=%zu, not a target",
           LevelName(level_), KeyShape(keyParams).c_str(), toString(keyFormat).c_str(),
           keyData.size());
      LOGD("importKey: params=%s", ParamsDesc(keyParams).c_str());
    }
    if (!ta) {
      if (real_) {
        LOGD("importKey: forwarding to real HAL (not a target)");
        ForwardGuard g;
        auto st = real_->importKey(keyParams, keyFormat, keyData, hardware_attestation_key, out);
        if (!st.isOk()) LOGW("importKey: FAILED in the real HAL: %s", StatusDesc(st).c_str());
        return st;
      }
      return NoRealHal(__func__);
    }
    // Match generateKey's storage-key invariant. A STORAGE_KEY blob must be minted by the real
    // KeyMint instance that will later unwrap it via convertStorageKeyToEphemeral().
    if (IsStorageKeyRequest(keyParams)) {
      if (real_) {
        LOGI("importKey: STORAGE_KEY requested; forwarding to the real %s HAL (hardware-owned, "
             "no simulated fallback)", LevelName(level_));
        ForwardGuard g;
        auto st = real_->importKey(keyParams, keyFormat, keyData, hardware_attestation_key, out);
        if (!st.isOk())
          LOGW("importKey: STORAGE_KEY FAILED in the real HAL: %s", StatusDesc(st).c_str());
        if (t.hardware_mode && st.isOk()) {
          auto valid = ValidateStrictHardwareResult("importKey/storage", *domain_, *out);
          if (!valid.isOk()) return valid;
        }
        return st;
      }
      LOGW("importKey: STORAGE_KEY requested but no real HAL exists; refusing simulated fallback");
      return NoRealHal(__func__);
    }
    // Imported auth/state-bound keys need the same real authenticator HMAC/state as generated ones.
    // Keep them in hardware. If the caller supplied one of our synthetic attest keys, the genuine HAL
    // cannot consume it; drop only that unusable attestation-key reference rather than importing the
    // private key into a TA that cannot validate the device's HATs.
    if (RequiresRealHardwareState(keyParams)) {
      if (!real_) {
        LOGW("importKey: auth/state-bound key requested but no real HAL exists; refusing simulated "
             "fallback");
        return NoRealHal(__func__);
      }
      std::optional<AttestationKey> real_attest_key = hardware_attestation_key;
      if (attestationKey && IsOurs(attestationKey->keyBlob)) {
        if (t.hardware_mode) {
          LOGW("importKey: strict hardware auth/state-bound import references a legacy TES software "
               "ATTEST_KEY; refusing to sever the delegated graph");
          return Status(static_cast<int32_t>(ErrorCode::INVALID_KEY_BLOB));
        }
        LOGW("importKey: auth/state-bound key names one of our attest keys; dropping that synthetic "
             "attest-key reference so the key remains hardware-authenticated");
        real_attest_key.reset();
      }
      LOGI("importKey: auth/state-bound key; forwarding to the real %s HAL (hardware-owned, no "
           "simulated fallback)", LevelName(level_));
      ForwardGuard g;
      auto st = real_->importKey(keyParams, keyFormat, keyData, real_attest_key, out);
      if (!st.isOk())
        LOGW("importKey: auth/state-bound key FAILED in the real HAL: %s", StatusDesc(st).c_str());
      if (t.hardware_mode && st.isOk()) {
          auto valid = ValidateStrictHardwareResult("importKey/auth", *domain_, *out);
          if (!valid.isOk()) return valid;
        }
        return st;
    }

    // As in generateKey, an ordinary symmetric key is forwarded rather than simulated.
    if (!IsAsymmetricKeyRequest(keyParams)) {
      if (real_) {
        LOGI("importKey: symmetric key; forwarding to the real HAL (never attested, kept in the "
             "real TEE)");
        ForwardGuard g;
        auto st = real_->importKey(keyParams, keyFormat, keyData, hardware_attestation_key, out);
        if (!st.isOk())
          LOGW("importKey: FAILED in the real HAL (symmetric): %s", StatusDesc(st).c_str());
        if (t.hardware_mode && st.isOk()) {
          auto valid = ValidateStrictHardwareResult("importKey/symmetric", *domain_, *out);
          if (!valid.isOk()) return valid;
        }
        return st;
      }
      return NoRealHal(__func__);
    }
    // Strict hardware mode imports the private/secret material into the genuine level-specific
    // KeyMint. The software TA is allowed to replace the returned certificate chain, but it never
    // receives the imported private key and never owns the resulting key blob.
    if (t.hardware_mode) {
      if (!real_) {
        LOGW("importKey: strict hardware mode has no real %s HAL; refusing software fallback",
             LevelName(level_));
        return NoRealHal(__func__);
      }

      std::optional<AttestationKey> real_attest_key = hardware_attestation_key;
      if (attestationKey && IsOurs(attestationKey->keyBlob)) {
        LOGW("importKey: strict hardware mode references a legacy TES software ATTEST_KEY; "
             "refusing silent graph rewrite. Regenerate the parent inside real %s first",
             LevelName(level_));
        return Status(static_cast<int32_t>(ErrorCode::INVALID_KEY_BLOB));
      }

      KeyCreationResult real_result;
      {
        ForwardGuard g;
        auto st = real_->importKey(keyParams, keyFormat, keyData, real_attest_key, &real_result);
        if (!st.isOk()) {
          LOGW("importKey: strict hardware import FAILED in real %s HAL: %s",
               LevelName(level_), StatusDesc(st).c_str());
          return st;
        }
      }

      auto valid = ValidateStrictHardwareResult("importKey", *domain_, real_result);
      if (!valid.isOk()) return valid;

      // Symmetric/import-only results may have no certificate at all. In that case the hardware
      // result is already complete and must be returned unchanged.
      if (real_result.certificateChain.empty()) {
        *out = std::move(real_result);
        LOGI("importKey: strict hardware import kept real %s blob with no attestation chain",
             LevelName(level_));
        return ndk::ScopedAStatus::ok();
      }

      // A real delegated ATTEST_KEY is the cryptographic parent of this certificate. Re-signing the
      // child directly with the profile keybox would make its signature stop verifying under the
      // parent public key while keystore2 still appends that parent's stored chain — an impossible
      // A->B graph. In strict hardware mode preserve the genuine child signature. The parent
      // certificate itself is re-rooted independently (including the inline RKP path), so the whole
      // chain remains cryptographically coherent without moving either private key out of hardware.
      if (real_attest_key.has_value()) {
        *out = std::move(real_result);
        LOGI("importKey: strict hardware delegated import preserved real %s child signature; "
             "parent ATTEST_KEY chain remains authoritative",
             LevelName(level_));
        return ndk::ScopedAStatus::ok();
      }

      const auto& leaf = real_result.certificateChain.front().encodedCertificate;
      TsCreationResult* patched = nullptr;

      int32_t attest_level = -1;
      int32_t keymint_level = -1;
      const int32_t provenance = teesim_km_attestation_security_levels(
          leaf.data(), leaf.size(), &attest_level, &keymint_level);

      int32_t rc = 0;
      const char* cert_mode = nullptr;
      if (provenance == 0) {
        cert_mode = "patched-attestation";
        rc = teesim_km_patch_attestation(ta.get(), leaf.data(), leaf.size(), &patched);
      } else if (provenance == 1) {
        cert_mode = "reissued-certificate";
        rc = teesim_km_reissue_certificate(ta.get(), leaf.data(), leaf.size(), &patched);
      } else {
        cert_mode = "invalid-certificate";
        rc = provenance;
      }

      if (rc != 0) {
        // The key is already inside the requested hardware security level. Preserve that invariant
        // even if certificate rewriting cannot be produced.
        LOGW("importKey: hardware key imported but %s failed rc=%d(%s); keeping genuine "
             "%s certificate chain rather than falling back to software",
             cert_mode, rc, teesim_km_err_name(rc), LevelName(level_));
        *out = std::move(real_result);
        return ndk::ScopedAStatus::ok();
      }

      out->keyBlob = std::move(real_result.keyBlob);
      out->keyCharacteristics = std::move(real_result.keyCharacteristics);
      const size_t n = teesim_km_result_num_certs(patched);
      out->certificateChain.resize(n);
      for (size_t i = 0; i < n; ++i) {
        const uint8_t* cert = nullptr;
        size_t cert_len = 0;
        teesim_km_result_cert(patched, i, &cert, &cert_len);
        out->certificateChain[i].encodedCertificate.assign(cert, cert + cert_len);
      }
      teesim_km_free_result(patched);
      LOGI("importKey: strict hardware import kept real %s key blob and emitted %zu-cert chain "
           "(%s)",
           LevelName(level_), out->certificateChain.size(), cert_mode);
      return ndk::ScopedAStatus::ok();
    }

    // As in generateKey: a foreign attest key can't be used by our TA — forward instead.
    if (attestationKey && !IsOurs(attestationKey->keyBlob)) {
      if (real_) {
        LOGI("importKey: attest key is not ours; forwarding to real HAL");
        ForwardGuard g;
        auto st = real_->importKey(keyParams, keyFormat, keyData, hardware_attestation_key, out);
        if (!st.isOk()) LOGW("importKey: FAILED in the real HAL: %s", StatusDesc(st).c_str());
        return st;
      }
      return NoRealHal(__func__);
    }
    auto km = ToKmVec(keyParams);
    auto ak = MakeAttestKey(attestationKey);
    TsCreationResult* res = nullptr;
    ApplyTimingDelay(t.timing.ta_call, "ta-call", t.id);
    int32_t rc = teesim_km_import_key(ta.get(), km.data(), km.size(),
                                      static_cast<int32_t>(keyFormat), keyData.data(), keyData.size(),
                                      ak.blob, ak.blob_len, ak.params.data(), ak.params.size(),
                                      ak.issuer, ak.issuer_len, &res);
    if (rc != 0) {
      LOGW("importKey: FAILED in the TA: rc=%d(%s)", rc, teesim_km_err_name(rc));
      return Status(rc);
    }
    FillCreationResult(res, out);
    teesim_km_free_result(res);
    LOGI("importKey: emitted %zu-cert chain (imported into the TA) key=%s blob_len=%zu",
         out->certificateChain.size(), BlobTag(out->keyBlob).c_str(), out->keyBlob.size());
    return ndk::ScopedAStatus::ok();
  }

  ndk::ScopedAStatus begin(KeyPurpose purpose, const std::vector<uint8_t>& keyBlob,
                           const std::vector<KeyParameter>& params,
                           const std::optional<HardwareAuthToken>& authToken,
                           BeginResult* out) override {
    LogContext lc_(RequestCtx());
    const std::string blob_tag = BlobTag(keyBlob);
    // One line per begin, written once the outcome is known: it names the operation every later
    // line of it carries. A failure carries the same description.
    const std::string what = "purpose=" + toString(purpose) + ", key=" + blob_tag +
                             ", blob_len=" + std::to_string(keyBlob.size()) +
                             ", params=" + ParamsDesc(params);
    const RequestTarget current = ProfileForRequest(params, AIBinder_getCallingUid(), level_);
    std::vector<uint8_t> hardware_blob;
    bool had_hardware_envelope = false;
    auto envelope_status =
        HardwareBlobForDomain("begin", *domain_, keyBlob, &hardware_blob, &had_hardware_envelope);
    if (!envelope_status.isOk()) return envelope_status;
    const bool software_blob = !had_hardware_envelope && IsOurs(keyBlob);
    if (current.hardware_mode && software_blob) {
      LOGW("begin: strict hardware profile attempted to use legacy TES software key=%s; "
           "refusing software execution. The application must regenerate this alias in real %s",
           blob_tag.c_str(), LevelName(level_));
      return Status(static_cast<int32_t>(ErrorCode::INVALID_KEY_BLOB));
    }
    if (current.ta) ApplyTimingDelay(current.timing.operation_start, "operation-start", current.id);
    if (!software_blob) {
      if (real_) {
        if (current.hardware_mode) {
          auto ready = RequireBackendLifecycleSynced("begin", *domain_);
          if (!ready.isOk()) return ready;
          auto bound = ValidateKnownHardwareBlobDomain("begin", *domain_, keyBlob);
          if (!bound.isOk()) return bound;
        }
        ForwardGuard g;
        auto st = real_->begin(purpose, hardware_blob, params, authToken, out);
        if (!st.isOk()) {
          LOGW("begin: FAILED in the real HAL: %s; %s", StatusDesc(st).c_str(), what.c_str());
          return st;
        }
        if (out->operation) {
          // The id is minted here and printed on both this line and every later line of the
          // operation, so a finish that fails names the begin that carried its nonce.
          std::string op_id = NextForwardedOpId();
          LOGD("begin: %s -> real HAL op[%s/%s]", what.c_str(), blob_tag.c_str(), op_id.c_str());
          if (current.hardware_mode) RememberHardwareBlob(*domain_, keyBlob);
          out->operation = ndk::SharedRefBase::make<ForwardedKeyMintOperation>(
              out->operation, blob_tag, std::move(op_id), teesim_log_context(), domain_);
        }
        return st;
      }
      return NoRealHal(__func__);
    }
    TaPtr ta = WaitForDefaultTa(level_);
    if (!ta) return NoTa(__func__);

    const bool needs_strongbox_slot = level_ == SecurityLevel::STRONGBOX;
    if (needs_strongbox_slot && !TryAcquireStrongBoxOperation()) {
      LOGW("begin: simulated StrongBox operation table full (%u active)",
           g_strongbox_active_ops.load(std::memory_order_relaxed));
      return Status(static_cast<int32_t>(ErrorCode::TOO_MANY_OPERATIONS));
    }

    auto km = ToKmVec(params);
    TsAuthToken at;
    TsBeginResult* res = nullptr;
    ApplyTimingDelay(current.timing.ta_call, "ta-call", current.id);
    int32_t rc = teesim_km_begin(ta.get(), static_cast<int32_t>(purpose), keyBlob.data(),
                                 keyBlob.size(), km.data(), km.size(), FlattenAuth(authToken, &at),
                                 &res);
    if (rc != 0) {
      if (needs_strongbox_slot) ReleaseStrongBoxOperation();
      LOGW("begin: FAILED in the TA: rc=%d(%s); %s", rc, teesim_km_err_name(rc), what.c_str());
      return Status(rc);
    }
    out->challenge = teesim_km_begin_challenge(res);
    size_t n = teesim_km_begin_num_params(res);
    out->params.reserve(n);
    for (size_t i = 0; i < n; ++i) {
      KmParam p{};
      teesim_km_begin_param(res, i, &p);
      out->params.push_back(FromKm(p));
    }
    int64_t op_handle = teesim_km_begin_op_handle(res);
    teesim_km_free_begin(res);
    LOGD("begin: %s -> TA op[%s/%s]", what.c_str(), blob_tag.c_str(), OpId(op_handle).c_str());
    out->operation =
        ndk::SharedRefBase::make<TeesimKeyMintOperation>(
            ta, op_handle, blob_tag, teesim_log_context(), needs_strongbox_slot,
            current.timing.ta_call);
    return ndk::ScopedAStatus::ok();
  }

  ndk::ScopedAStatus deleteKey(const std::vector<uint8_t>& keyBlob) override {
    LogContext lc_(RequestCtx());
    std::vector<uint8_t> hardware_blob;
    bool had_hardware_envelope = false;
    auto envelope_status =
        HardwareBlobForDomain("deleteKey", *domain_, keyBlob, &hardware_blob, &had_hardware_envelope);
    if (!envelope_status.isOk()) return envelope_status;
    const bool software_blob = !had_hardware_envelope && IsOurs(keyBlob);

    // keystore2 garbage-collects superseded real blobs on its own thread; only a delete of one of
    // our software keys is an event worth INFO.
    if (software_blob) {
      LOGI("deleteKey: key=%s, blob_len=%zu, ours=1", BlobTag(keyBlob).c_str(), keyBlob.size());
    } else {
      LOGD("deleteKey: key=%s, blob_len=%zu, ours=0", BlobTag(keyBlob).c_str(), keyBlob.size());
    }
    if (!software_blob) {
      if (real_) {
        ForwardGuard g;
        auto st = real_->deleteKey(hardware_blob);
        if (st.isOk()) ForgetHardwareBlob(keyBlob);
        return st;
      }
      return ndk::ScopedAStatus::ok();
    }
    TaPtr ta = WaitForDefaultTa(level_);
    if (!ta) return NoTa(__func__);
    return Status(teesim_km_delete_key(ta.get(), keyBlob.data(), keyBlob.size()));
  }

  ndk::ScopedAStatus upgradeKey(const std::vector<uint8_t>& keyBlobToUpgrade,
                                const std::vector<KeyParameter>& upgradeParams,
                                std::vector<uint8_t>* out) override {
    LogContext lc_(RequestCtx());
    // An upgrade is the one operation that legitimately replaces a blob, so it is
    // the one place a key can quietly stop being the key that encrypted an app's
    // data. Log what went in and what came back out.
    LOGI("upgradeKey: key=%s, blob_len=%zu, ours=%d, params=%s", BlobTag(keyBlobToUpgrade).c_str(),
         keyBlobToUpgrade.size(), IsOurs(keyBlobToUpgrade), ParamsDesc(upgradeParams).c_str());
    const RequestTarget current =
        ProfileForRequest(upgradeParams, AIBinder_getCallingUid(), level_);
    std::vector<uint8_t> hardware_blob;
    bool had_hardware_envelope = false;
    auto envelope_status = HardwareBlobForDomain(
        "upgradeKey", *domain_, keyBlobToUpgrade, &hardware_blob, &had_hardware_envelope);
    if (!envelope_status.isOk()) return envelope_status;
    const bool software_blob = !had_hardware_envelope && IsOurs(keyBlobToUpgrade);
    if (current.hardware_mode && software_blob) {
      LOGW("upgradeKey: strict hardware profile cannot upgrade legacy TES software key=%s into "
           "hardware without private-key migration; refusing", BlobTag(keyBlobToUpgrade).c_str());
      return Status(static_cast<int32_t>(ErrorCode::INVALID_KEY_BLOB));
    }
    if (!software_blob) {
      if (real_) {
        if (current.hardware_mode) {
          auto bound = ValidateKnownHardwareBlobDomain("upgradeKey", *domain_, keyBlobToUpgrade);
          if (!bound.isOk()) return bound;
        }
        ForwardGuard g;
        auto st = real_->upgradeKey(hardware_blob, upgradeParams, out);
        if (!st.isOk()) {
          LOGW("upgradeKey: FAILED in the real HAL: %s", StatusDesc(st).c_str());
          return st;
        }
        LOGI("upgradeKey: real HAL returned key=%s, blob_len=%zu",
             out ? BlobTag(*out).c_str() : "-", out ? out->size() : 0);
        if ((current.hardware_mode || had_hardware_envelope) && out) {
          auto wrapped = WrapHardwareBlob(level_, *out);
          if (wrapped.empty()) {
            LOGE("upgradeKey: real HAL returned an invalid/non-hardware blob for %s",
                 domain_->Label());
            return Status(static_cast<int32_t>(ErrorCode::INVALID_KEY_BLOB));
          }
          ForgetHardwareBlob(keyBlobToUpgrade);
          *out = std::move(wrapped);
          RememberHardwareBlob(*domain_, *out);
        }
        return st;
      }
      return NoRealHal(__func__);
    }
    TaPtr ta = WaitForDefaultTa(level_);
    if (!ta) return NoTa(__func__);
    auto km = ToKmVec(upgradeParams);
    uint8_t* buf = nullptr;
    size_t len = 0;
    int32_t rc = teesim_km_upgrade_key(ta.get(), keyBlobToUpgrade.data(), keyBlobToUpgrade.size(),
                                       km.data(), km.size(), &buf, &len);
    if (rc != 0) {
      LOGW("upgradeKey: FAILED in the TA: rc=%d(%s)", rc, teesim_km_err_name(rc));
      return Status(rc);
    }
    out->assign(buf, buf + len);
    LOGI("upgradeKey: TA returned key=%s, blob_len=%zu", BlobTag(*out).c_str(), out->size());
    teesim_km_free_buf(buf, len);
    return ndk::ScopedAStatus::ok();
  }

  ndk::ScopedAStatus getKeyCharacteristics(const std::vector<uint8_t>& keyBlob,
                                           const std::vector<uint8_t>& appId,
                                           const std::vector<uint8_t>& appData,
                                           std::vector<KeyCharacteristics>* out) override {
    LogContext lc_(RequestCtx());
    LOGD("getKeyCharacteristics: key=%s, blob_len=%zu, ours=%d", BlobTag(keyBlob).c_str(),
         keyBlob.size(), IsOurs(keyBlob));
    const RequestTarget current = ProfileForRequest({}, AIBinder_getCallingUid(), level_);
    std::vector<uint8_t> hardware_blob;
    bool had_hardware_envelope = false;
    auto envelope_status = HardwareBlobForDomain(
        "getKeyCharacteristics", *domain_, keyBlob, &hardware_blob, &had_hardware_envelope);
    if (!envelope_status.isOk()) return envelope_status;
    const bool software_blob = !had_hardware_envelope && IsOurs(keyBlob);
    if (current.hardware_mode && software_blob) {
      LOGW("getKeyCharacteristics: strict hardware profile still owns legacy TES software key=%s; "
           "refusing to present it as a hardware key", BlobTag(keyBlob).c_str());
      return Status(static_cast<int32_t>(ErrorCode::INVALID_KEY_BLOB));
    }
    if (!software_blob) {
      if (real_) {
        if (current.hardware_mode) {
          auto bound = ValidateKnownHardwareBlobDomain("getKeyCharacteristics", *domain_, keyBlob);
          if (!bound.isOk()) return bound;
        }
        ForwardGuard g;
        auto st = real_->getKeyCharacteristics(hardware_blob, appId, appData, out);
        if (st.isOk() && current.hardware_mode) RememberHardwareBlob(*domain_, keyBlob);
        return st;
      }
      return NoRealHal(__func__);
    }
    TaPtr ta = WaitForDefaultTa(level_);
    if (!ta) return NoTa(__func__);
    TsCharacteristics* res = nullptr;
    int32_t rc = teesim_km_get_key_characteristics(ta.get(), keyBlob.data(), keyBlob.size(),
                                                   appId.data(), appId.size(), appData.data(),
                                                   appData.size(), &res);
    if (rc != 0) return Status(rc);
    size_t n_chars = teesim_km_chars_num(res);
    out->resize(n_chars);
    for (size_t ci = 0; ci < n_chars; ++ci) {
      int32_t level = 0;
      size_t n_params = teesim_km_chars_entry(res, ci, &level);
      (*out)[ci].securityLevel = static_cast<SecurityLevel>(level);
      (*out)[ci].authorizations.reserve(n_params);
      for (size_t pi = 0; pi < n_params; ++pi) {
        KmParam km{};
        teesim_km_chars_param(res, ci, pi, &km);
        (*out)[ci].authorizations.push_back(FromKm(km));
      }
    }
    teesim_km_free_chars(res);
    return ndk::ScopedAStatus::ok();
  }

  ndk::ScopedAStatus convertStorageKeyToEphemeral(const std::vector<uint8_t>& storageKeyBlob,
                                                  std::vector<uint8_t>* out) override {
    LogContext lc_(RequestCtx());
    const std::string blob_tag = BlobTag(storageKeyBlob);
    std::vector<uint8_t> hardware_blob;
    bool had_hardware_envelope = false;
    auto envelope_status = HardwareBlobForDomain(
        "convertStorageKeyToEphemeral", *domain_, storageKeyBlob, &hardware_blob,
        &had_hardware_envelope);
    if (!envelope_status.isOk()) return envelope_status;

    // A valid STORAGE_KEY is always real-HAL-owned. If an old/malformed build ever produced one of
    // our marked blobs, forwarding it would only hand opaque simulator bytes to hardware. Fail
    // explicitly instead of attempting a software conversion with different per-boot semantics.
    if (!had_hardware_envelope && IsOurs(storageKeyBlob)) {
      LOGW("convertStorageKeyToEphemeral: refusing simulator-owned blob key=%s len=%zu; "
           "STORAGE_KEY must be hardware-owned", blob_tag.c_str(), storageKeyBlob.size());
      return Status(static_cast<int32_t>(ErrorCode::STORAGE_KEY_UNSUPPORTED));
    }
    if (!real_) {
      LOGW("convertStorageKeyToEphemeral: key=%s len=%zu but no real %s HAL exists",
           blob_tag.c_str(), storageKeyBlob.size(), LevelName(level_));
      return NoRealHal(__func__);
    }
    LOGD("convertStorageKeyToEphemeral: forwarding key=%s len=%zu to real %s HAL",
         blob_tag.c_str(), storageKeyBlob.size(), LevelName(level_));
    ForwardGuard g;
    auto st = real_->convertStorageKeyToEphemeral(hardware_blob, out);
    if (!st.isOk()) {
      LOGW("convertStorageKeyToEphemeral: FAILED in the real HAL: %s key=%s len=%zu",
           StatusDesc(st).c_str(), blob_tag.c_str(), storageKeyBlob.size());
    }
    return st;
  }

  // Everything below is not simulated; forward to the real HAL when present.
  ndk::ScopedAStatus addRngEntropy(const std::vector<uint8_t>& data) override {
    LogContext lc_(RequestCtx());
    ForwardGuard g;
    return real_ ? real_->addRngEntropy(data) : ndk::ScopedAStatus::ok();
  }
  // Wrapped-key import is always forwarded to the real HAL, even for a target app: the result is a
  // real, unmarked blob whose later operations forward to real hardware, so it is never re-rooted
  // under the keybox. Simulating it would mean unwrapping with the wrapping key inside our TA, which
  // we only hold if that wrapping key was itself minted by us — a rare case not worth the surface.
  ndk::ScopedAStatus importWrappedKey(const std::vector<uint8_t>& wrappedKeyData,
                                      const std::vector<uint8_t>& wrappingKeyBlob,
                                      const std::vector<uint8_t>& maskingKey,
                                      const std::vector<KeyParameter>& unwrappingParams,
                                      int64_t passwordSid, int64_t biometricSid,
                                      KeyCreationResult* out) override {
    LogContext lc_(RequestCtx());
    const RequestTarget t =
        ProfileForRequest(unwrappingParams, AIBinder_getCallingUid(), level_);
    std::vector<uint8_t> hardware_wrapping_blob;
    bool had_hardware_envelope = false;
    auto envelope_status = HardwareBlobForDomain(
        "importWrappedKey", *domain_, wrappingKeyBlob, &hardware_wrapping_blob,
        &had_hardware_envelope);
    if (!envelope_status.isOk()) return envelope_status;

    if (t.hardware_mode && !had_hardware_envelope && IsOurs(wrappingKeyBlob)) {
      LOGW("importWrappedKey: strict hardware profile supplied a TES software wrapping key=%s; "
           "refusing to unwrap outside real %s", BlobTag(wrappingKeyBlob).c_str(),
           LevelName(level_));
      return Status(static_cast<int32_t>(ErrorCode::INVALID_KEY_BLOB));
    }
    if (!real_) return NoRealHal(__func__);

    ForwardGuard g;
    auto st = real_->importWrappedKey(wrappedKeyData, hardware_wrapping_blob, maskingKey,
                                      unwrappingParams, passwordSid, biometricSid, out);
    if (!st.isOk()) {
      LOGW("importWrappedKey: FAILED in real %s HAL: %s", LevelName(level_),
           StatusDesc(st).c_str());
      return st;
    }
    if (t.hardware_mode) {
      auto valid = ValidateStrictHardwareResult("importWrappedKey", *domain_, *out);
      if (!valid.isOk()) return valid;
    }
    return st;
  }
  ndk::ScopedAStatus deleteAllKeys() override {
    LogContext lc_(RequestCtx());
    ForwardGuard g;
    return real_ ? real_->deleteAllKeys() : ndk::ScopedAStatus::ok();
  }
  ndk::ScopedAStatus destroyAttestationIds() override {
    LogContext lc_(RequestCtx());
    ForwardGuard g;
    return real_ ? real_->destroyAttestationIds() : ndk::ScopedAStatus::ok();
  }
  // deviceLocked belongs to the genuine secure-authentication state. Keys that depend on HATs,
  // UNLOCKED_DEVICE_REQUIRED, trusted presence, or trusted confirmation are deliberately never minted
  // in our TA (RequiresRealHardwareState), so relaying this transition to the real HAL is sufficient and
  // avoids pretending our isolated TA participates in the device's Gatekeeper/shared-secret state.
  ndk::ScopedAStatus deviceLocked(bool passwordOnly,
                                  const std::optional<secureclock::TimeStampToken>& tst) override {
    LogContext lc_(RequestCtx());
    ForwardGuard g;
    // deviceLocked is deprecated in the AIDL but still part of the interface we implement, so we
    // relay it verbatim; suppress the deprecation warning for the one forwarding call.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    return real_ ? real_->deviceLocked(passwordOnly, tst) : ndk::ScopedAStatus::ok();
#pragma clang diagnostic pop
  }
  ndk::ScopedAStatus earlyBootEnded() override {
    LogContext lc_(RequestCtx());
    {
      std::lock_guard<std::mutex> lk(g_hw_lifecycle_mu);
      g_hw_early_boot_ended = true;
    }
    // Compatibility TAs receive the same monotonic transition, but strict hardware ownership still
    // depends on the genuine backend accepting it.
    for (const auto& ta : AllProfileTas()) {
      int32_t rc = teesim_km_early_boot_ended(ta.get());
      if (rc != 0) LOGW("earlyBootEnded: TA rejected rc=%d(%s)", rc, teesim_km_err_name(rc));
    }
    if (!real_) return NoRealHal(__func__);
    ForwardGuard g;
    auto st = real_->earlyBootEnded();
    domain_->early_boot_synced.store(st.isOk(), std::memory_order_release);
    return st;
  }
  ndk::ScopedAStatus getRootOfTrustChallenge(std::array<uint8_t, 16>* out) override {
    LogContext lc_(RequestCtx());
    ForwardGuard g;
    return real_ ? real_->getRootOfTrustChallenge(out) : NoRealHal(__func__);
  }
  ndk::ScopedAStatus getRootOfTrust(const std::array<uint8_t, 16>& challenge,
                                    std::vector<uint8_t>* out) override {
    LogContext lc_(RequestCtx());
    ForwardGuard g;
    return real_ ? real_->getRootOfTrust(challenge, out) : NoRealHal(__func__);
  }
  ndk::ScopedAStatus sendRootOfTrust(const std::vector<uint8_t>& rootOfTrust) override {
    LogContext lc_(RequestCtx());
    ForwardGuard g;
    return real_ ? real_->sendRootOfTrust(rootOfTrust) : ndk::ScopedAStatus::ok();
  }
  // Record the additional attestation info (e.g. MODULE_HASH on Android 16) on our TAs as well, so a
  // key we attest carries the same value keystore2 pushes to the real HAL and still matches a genuine
  // device. Applied to every profile since the info is device-wide; best-effort per TA.
  ndk::ScopedAStatus setAdditionalAttestationInfo(const std::vector<KeyParameter>& info) override {
    LogContext lc_(RequestCtx());
    // Latch keystore2's MODULE_HASH as the authoritative value to seed TAs built later this boot: it
    // is the exact bytes the real HAL got, so it matches a genuine device byte-for-byte.
    for (const auto& p : info) {
      if (p.tag == Tag::MODULE_HASH && p.value.getTag() == KeyParameterValue::blob) {
        std::lock_guard<std::mutex> lk(g_cfg_mu);
        g_module_hash = p.value.get<KeyParameterValue::blob>();
      }
    }
    {
      std::lock_guard<std::mutex> lk(g_hw_lifecycle_mu);
      g_hw_additional_attestation_info = info;
    }
    auto km = ToKmVec(info);
    for (const auto& ta : AllProfileTas()) {
      int32_t rc = teesim_km_set_additional_attestation_info(ta.get(), km.data(), km.size());
      if (rc != 0)
        LOGW("setAdditionalAttestationInfo: TA rejected rc=%d(%s)", rc, teesim_km_err_name(rc));
    }
    if (!real_) return NoRealHal(__func__);
    ForwardGuard g;
    auto st = real_->setAdditionalAttestationInfo(info);
    domain_->additional_info_synced.store(st.isOk(), std::memory_order_release);
    return st;
  }

 private:
  struct AttestKeyArgs {
    const uint8_t* blob = nullptr;
    size_t blob_len = 0;
    std::vector<KmParam> params;
    const uint8_t* issuer = nullptr;
    size_t issuer_len = 0;
  };

  static AttestKeyArgs MakeAttestKey(const std::optional<AttestationKey>& ak) {
    AttestKeyArgs a;
    if (ak) {
      a.blob = ak->keyBlob.data();
      a.blob_len = ak->keyBlob.size();
      a.params = ToKmVec(ak->attestKeyParams);
      a.issuer = ak->issuerSubjectName.data();
      a.issuer_len = ak->issuerSubjectName.size();
    }
    return a;
  }

  // Patch mode: the real hardware generates and attests the key; we keep its genuine, hardware-backed
  // key blob and re-sign only the attestation chain under the keybox, with the root of trust patched
  // to locked/Verified. The kept blob is unmarked, so later operations on the key forward to the real
  // HAL. Falls back to generation only if the real HAL declines outright or the re-signing fails.
  ndk::ScopedAStatus PatchAttest(::Ta* ta, const std::vector<KeyParameter>& keyParams,
                                 KeyCreationResult* out, bool hardware_required = false) {
    KeyCreationResult real;
    Elapsed real_el;
    {
      ForwardGuard g;
      // No attest key here — a request that carries one is handled before we reach patch mode (ours is
      // signed in the TA, a foreign one is forwarded whole). Let the real hardware attest with its own
      // batch key; we keep only the leaf and re-sign it under the keybox.
      auto st = real_->generateKey(keyParams, std::nullopt, &real);
      if (!st.isOk()) {
        if (hardware_required) {
          LOGW("PatchAttest: real generateKey failed (%s) after %llums; hardware-backed "
               "authorization is required, so simulated fallback is forbidden",
               StatusDesc(st).c_str(), real_el.Ms());
          return st;
        }
        LOGW("PatchAttest: real generateKey failed (%s) after %llums; generating instead",
             StatusDesc(st).c_str(), real_el.Ms());
        return Simulate(ta, keyParams, std::nullopt, out);
      }
    }
    const unsigned long long real_ms = real_el.Ms();
    if (hardware_required) {
      auto valid = ValidateStrictHardwareResult("PatchAttest", *domain_, real);
      if (!valid.isOk()) return valid;
    }
    if (real.certificateChain.empty()) {
      // A symmetric key (AES/HMAC/3DES) never has a certificate, so an empty chain is the real HAL
      // saying there is nothing to attest — not a failure. Keep the hardware key exactly as it came
      // back: minting our own would move the app's key material into the software TA for no gain in
      // attestation, and an auth-bound key would then be checked against a TA that holds no device
      // HMAC key ("no device HMAC key; accepting auth_token on presence"), which is how fingerprint-
      // bound keys start failing with KEY_USER_NOT_AUTHENTICATED.
      *out = std::move(real);
      LOGI("PatchAttest: real HAL returned no certificates (nothing to attest); keeping the real key "
           "key=%s blob_len=%zu real=%llums",
           BlobTag(out->keyBlob).c_str(), out->keyBlob.size(), real_ms);
      return ndk::ScopedAStatus::ok();
    }
    LOGD("PatchAttest: real HAL returned %zu cert(s) in %llums; re-signing only the leaf under the "
         "keybox",
         real.certificateChain.size(), real_ms);
    const auto& leaf = real.certificateChain.front().encodedCertificate;
    TsCreationResult* res = nullptr;
    Elapsed ta_el;

    // A hardware asymmetric key without an attestation challenge may carry a plain self-signed
    // certificate rather than KeyDescription. That is especially common for locally-created
    // ATTEST_KEY parents. Distinguish that valid case from malformed attestation data:
    //   0 -> KeyDescription present: patch TES-owned attestation fields.
    //   1 -> valid X.509, no KeyDescription: reissue the same hardware public key under keybox.
    //  <0 -> malformed X.509/KeyDescription: never hide it behind generic certificate reissue.
    int32_t attest_level = -1;
    int32_t keymint_level = -1;
    const int32_t provenance = teesim_km_attestation_security_levels(
        leaf.data(), leaf.size(), &attest_level, &keymint_level);

    int32_t rc = 0;
    const char* cert_mode = nullptr;
    if (provenance == 0) {
      cert_mode = "patched-attestation";
      rc = teesim_km_patch_attestation(ta, leaf.data(), leaf.size(), &res);
    } else if (provenance == 1) {
      cert_mode = "reissued-certificate";
      rc = teesim_km_reissue_certificate(ta, leaf.data(), leaf.size(), &res);
    } else {
      rc = provenance;
      cert_mode = "invalid-certificate";
    }

    const unsigned long long ta_ms = ta_el.Ms();
    if (rc != 0) {
      if (hardware_required) {
        // The hardware key is valid and its authorization semantics are more important than
        // certificate rewriting. Strict mode never swaps in a software-owned key as recovery.
        LOGW("PatchAttest: %s failed rc=%d(%s); keeping the real hardware key/chain because "
             "software fallback is forbidden",
             cert_mode, rc, teesim_km_err_name(rc));
        *out = std::move(real);
        return ndk::ScopedAStatus::ok();
      }
      LOGW("PatchAttest: %s failed rc=%d(%s); generating instead", cert_mode, rc,
           teesim_km_err_name(rc));
      return Simulate(ta, keyParams, std::nullopt, out);
    }
    // Keep the real hardware key blob and characteristics; swap in the keybox-rooted, RoT-patched
    // chain we just built.
    out->keyBlob = real.keyBlob;
    out->keyCharacteristics = std::move(real.keyCharacteristics);
    size_t n = teesim_km_result_num_certs(res);
    out->certificateChain.resize(n);
    for (size_t i = 0; i < n; ++i) {
      const uint8_t* c = nullptr;
      size_t clen = 0;
      teesim_km_result_cert(res, i, &c, &clen);
      out->certificateChain[i].encodedCertificate.assign(c, c + clen);
    }
    teesim_km_free_result(res);
    // The key tag ties this creation to every later begin, upgrade and delete on the key, so a blob
    // seen at a begin can be traced back to the profile that signed it and whether it was patched or
    // minted.
    LOGI("PatchAttest: emitted %zu-cert chain (%s; real key blob kept, leaf re-rooted at keybox) "
         "key=%s blob_len=%zu real=%llums ta=%llums",
         out->certificateChain.size(), cert_mode, BlobTag(out->keyBlob).c_str(),
         out->keyBlob.size(), real_ms, ta_ms);
    return ndk::ScopedAStatus::ok();
  }

  ndk::ScopedAStatus Simulate(::Ta* ta, const std::vector<KeyParameter>& keyParams,
                              const std::optional<AttestationKey>& attestationKey,
                              const TsDelayRange& ta_call_delay, const std::string& profile_id,
                              KeyCreationResult* out) {
    auto km = ToKmVec(keyParams);
    auto ak = MakeAttestKey(attestationKey);
    TsCreationResult* res = nullptr;
    Elapsed ta_el;
    ApplyTimingDelay(ta_call_delay, "ta-call", profile_id);
    int32_t rc = teesim_km_generate_key(ta, km.data(), km.size(),
                                        ak.blob, ak.blob_len, ak.params.data(), ak.params.size(),
                                        ak.issuer, ak.issuer_len, &res);
    const unsigned long long ta_ms = ta_el.Ms();
    if (rc != 0) {
      LOGW("Simulate: FAILED in the TA: rc=%d(%s)", rc, teesim_km_err_name(rc));
      return Status(rc);
    }
    FillCreationResult(res, out);
    teesim_km_free_result(res);
    LOGI("Simulate: emitted %zu-cert chain (whole key minted in the TA) key=%s blob_len=%zu "
         "ta=%llums",
         out->certificateChain.size(), BlobTag(out->keyBlob).c_str(), out->keyBlob.size(), ta_ms);
    return ndk::ScopedAStatus::ok();
  }

  std::shared_ptr<HardwareBackendDomain> domain_;
  SecurityLevel level_;
  std::shared_ptr<IKeyMintDevice> real_;
};

}  // namespace

// --- C entry points ----------------------------------------------------------

extern "C" const char* teesim_hook_name(void) { return "keymint"; }

// Snapshot the usage map as a JSON array (see control.h). Built under the usage
// lock only; no crypto state is touched, so the daemon can poll this freely.
extern "C" char* teesim_usage_json_alloc(void) {
  std::string out = "[";
  {
    std::lock_guard<std::mutex> lk(g_usage_mu);
    bool first = true;
    for (const auto& kv : g_usage) {
      if (!first) out += ",";
      first = false;
      out += "{\"uid\":";
      out += std::to_string(kv.first);
      out += ",\"count\":";
      out += std::to_string(kv.second.count);
      out += ",\"lastBootMs\":";
      out += std::to_string(kv.second.last_boot_ms);
      out += ",\"pkg\":\"";
      // pkg is a plain package name or empty, but escape the JSON-significant bytes defensively.
      for (char c : kv.second.pkg) {
        if (c == '"' || c == '\\') out += '\\';
        out += c;
      }
      out += "\"}";
    }
  }
  out += "]";
  char* buf = static_cast<char*>(malloc(out.size() + 1));
  if (buf) memcpy(buf, out.c_str(), out.size() + 1);
  return buf;
}

extern "C" bool teesim_backend_domain_snapshot(int32_t security_level,
                                                  TsBackendDomainSnapshot* out) {
  if (!out) return false;
  std::memset(out, 0, sizeof(*out));
  std::shared_ptr<HardwareBackendDomain> domain;
  {
    std::lock_guard<std::mutex> lk(g_backend_domain_mu);
    auto it = g_backend_domains.find(security_level);
    if (it == g_backend_domains.end()) return false;
    domain = it->second.lock();
  }
  if (!domain || domain->dead.load(std::memory_order_acquire)) return false;

  out->present = 1;
  out->security_level = static_cast<int32_t>(domain->level);
  out->canonical_identity = domain->canonical_identity ? 1 : 0;
  out->remote = domain->remote ? 1 : 0;
  out->shared_secret_declared = domain->shared_secret_declared ? 1 : 0;
  out->shared_secret_bound = domain->shared_secret ? 1 : 0;
  out->secure_clock_declared = domain->secure_clock_declared ? 1 : 0;
  out->secure_clock_bound = domain->secure_clock ? 1 : 0;
  out->rkp_declared = domain->rkp_declared ? 1 : 0;
  out->rkp_bound = 0;
  if (domain->rkp_declared && !domain->rkp_instance.empty()) {
    const std::string rkp_service =
        std::string("android.hardware.security.keymint.IRemotelyProvisionedComponent/") +
        domain->rkp_instance;
    AIBinder* raw = AServiceManager_checkService(rkp_service.c_str());
    if (raw) {
      ndk::SpAIBinder binder(raw);  // adopts the strong reference; snapshot keeps no extra owner
      out->rkp_bound = 1;
    }
  }
  out->epoch = domain->epoch;
  std::snprintf(out->keymint_service, sizeof(out->keymint_service), "%s",
                domain->keymint_service.c_str());
  std::snprintf(out->rkp_instance, sizeof(out->rkp_instance), "%s",
                domain->rkp_instance.c_str());
  return true;
}

// Config-staging API (see common/control.h). teesim_cfg_begin/add_profile run on
// the control thread before the swap; only teesim_cfg_commit touches live tables.
extern "C" void teesim_cfg_begin(const TsBootInfo* boot) {
  g_staging.clear();
  g_stage_vb_key.assign(boot->verified_boot_key,
                        boot->verified_boot_key + boot->verified_boot_key_len);
  g_stage_vb_hash.assign(boot->verified_boot_hash,
                         boot->verified_boot_hash + boot->verified_boot_hash_len);
  g_stage_module_hash.assign(boot->module_hash, boot->module_hash + boot->module_hash_len);
  g_stage_locked = boot->device_locked;
  g_stage_vb_state = boot->verified_boot_state;
  g_stage_strongbox_ok = boot->strongbox_available;
  g_stage_attest_version_tee = boot->attest_version_tee;
  g_stage_attest_version_strongbox = boot->attest_version_strongbox;
}

extern "C" bool teesim_cfg_add_profile(const TsProfile* p) {
  // A real device runs a separate KeyMint instance per security level; we mirror that with one fixed-
  // level TA per level. Both are built from the same keybox and boot state, so their key-encryption
  // keys match and any of our blobs decrypts under either — but each stamps its own level into the
  // keys it mints, so operations read a key's characteristics at the level it was minted at with no
  // per-request override. `p->security_level` is retained only for the staged-profile log line.
  auto buildTa = [&](int32_t level) -> ::Ta* {
    return teesim_km_init_ex(p->keybox, p->keybox_len, level, p->os_version, p->os_patchlevel,
                             p->vendor_patchlevel, p->boot_patchlevel, g_stage_vb_key.data(),
                             g_stage_vb_key.size(), g_stage_vb_hash.data(), g_stage_vb_hash.size(),
                             g_stage_locked, g_stage_vb_state, g_stage_attest_version_tee,
                             g_stage_attest_version_strongbox, p->ids);
  };
  ::Ta* ta_tee = buildTa(static_cast<int32_t>(SecurityLevel::TRUSTED_ENVIRONMENT));
  ::Ta* ta_sb = buildTa(static_cast<int32_t>(SecurityLevel::STRONGBOX));
  if (!ta_tee || !ta_sb) {
    LOGE("teesim_cfg_add_profile: profile %s failed to build (bad keybox?)", p->id ? p->id : "?");
    if (ta_tee) teesim_km_destroy(ta_tee);
    if (ta_sb) teesim_km_destroy(ta_sb);
    return false;
  }
  Profile prof;
  prof.id = p->id ? p->id : "";
  prof.ta_tee = WrapTa(ta_tee);
  prof.ta_strongbox = WrapTa(ta_sb);
  const std::string mode = p->mode ? std::string(p->mode) : std::string("patch");
  prof.hardware_mode = mode == "hardware";
  prof.patch_mode = mode == "patch" || prof.hardware_mode;
  prof.timing.attestation =
      TsBoundedDelayRange(p->attestation_delay_min_ms, p->attestation_delay_max_ms);
  prof.timing.operation_start =
      TsBoundedDelayRange(p->operation_start_delay_min_ms, p->operation_start_delay_max_ms);
  prof.timing.ta_call = TsBoundedDelayRange(p->ta_call_delay_min_ms, p->ta_call_delay_max_ms);
  // Seed both instances with the device-wide MODULE_HASH so a generation-mode key either mints carries
  // the tag, independent of keystore2's one-shot delivery. Prefer keystore2's captured bytes; fall
  // back to the daemon's computed value when we never saw that call. The reference TA emits the tag
  // only for KeyMint v4+ attestations, so seeding an older-version profile is harmless.
  {
    std::vector<uint8_t> seed;
    {
      std::lock_guard<std::mutex> lk(g_cfg_mu);
      seed = g_module_hash.empty() ? g_stage_module_hash : g_module_hash;
    }
    SeedModuleHash(prof.ta_tee, seed);
    SeedModuleHash(prof.ta_strongbox, seed);
  }
  for (int i = 0; i < p->n_packages && p->packages; ++i) {
    if (!p->packages[i]) continue;
    // No package_users[] at all means an older daemon that only ever targeted the primary user.
    prof.packages.push_back({p->packages[i], p->package_users ? p->package_users[i] : 0});
  }
  for (int i = 0; i < p->n_uids && p->uids; ++i) {
    prof.uids.push_back(p->uids[i]);
    // uid_packages[] is aligned 1:1 with uids[]; a NULL array (older daemon) or a NULL/"" entry (a
    // raw uid:N target) just means the log will carry the bare uid.
    const char* name = (p->uid_packages && p->uid_packages[i]) ? p->uid_packages[i] : "";
    prof.uid_names.emplace_back(name);
  }
  LOGI("teesim_cfg_add_profile: staged profile '%s' (mode=%s, security_level=%s, %zu package(s), "
       "%zu uid(s))",
       prof.id.c_str(),
       prof.hardware_mode ? "hardware" : (prof.patch_mode ? "patch" : "generation"),
       LevelName(static_cast<SecurityLevel>(p->security_level)),
       prof.packages.size(), prof.uids.size());
  for (const auto& pkg : prof.packages)
    LOGD("teesim_cfg_add_profile:   package '%s' in user %d", pkg.name.c_str(), pkg.user_id);
  g_staging.push_back(std::move(prof));
  return true;
}

extern "C" int teesim_cfg_commit(uint64_t /*epoch*/, char* /*err*/, size_t /*err_len*/) {
  int n = 0;
  {
    std::lock_guard<std::mutex> lk(g_cfg_mu);
    g_profiles = std::move(g_staging);
    g_staging.clear();
    g_strongbox_ok = g_stage_strongbox_ok;
    n = static_cast<int>(g_profiles.size());
  }
  // Release anything parked in WaitForDefaultTa now that there is a TA to serve it.
  g_cfg_cv.notify_all();
  return n;
}

// True if `uid` belongs to a live target profile. The transact hook uses this to scope the RKP
// denial to our apps: when a target app's generateKey resolves a remote-provisioned attest key, we
// fail that lookup so keystore2 appends no real-hardware chain and our forced generation stays clean.
extern "C" bool teesim_is_target_uid(int32_t uid) {
  if (uid < 0) return false;
  std::lock_guard<std::mutex> lk(g_cfg_mu);
  for (const auto& prof : g_profiles) {
    for (int32_t u : prof.uids) {
      if (u == uid) return true;
    }
  }
  return false;
}

// RKP policy for a target caller.
//   0 = not targeted / unknown
//   1 = compatibility profile: the existing per-target RKP gate may deny on hybrid levels
//   2 = strict hardware profile: never deny RKP here; real TEE/StrongBox ownership takes precedence
//       over certificate re-rooting. RKP-only devices would otherwise lose their only hardware
//       attestation path and either fail or tempt an unsafe software fallback.
extern "C" int teesim_target_rkp_policy(int32_t uid) {
  if (uid < 0) return 0;
  std::lock_guard<std::mutex> lk(g_cfg_mu);
  for (const auto& prof : g_profiles) {
    for (int32_t u : prof.uids) {
      if (u != uid) continue;
      return prof.hardware_mode ? 2 : 1;
    }
  }
  return 0;
}

extern "C" bool teesim_cfg_resign(const char* profile_id, const uint8_t* leaf, size_t leaf_len,
                                  TsCertSink sink, void* ctx) {
  if (!profile_id || !leaf || leaf_len == 0 || !sink) return false;
  LOGI("teesim_cfg_resign: request for profile '%s' (leaf %zu bytes)", profile_id, leaf_len);
  TaPtr ta;
  {
    std::lock_guard<std::mutex> lk(g_cfg_mu);
    for (const auto& prof : g_profiles) {
      if (prof.id == profile_id) {
        // Re-signing is level-independent (same keybox and patched root of trust at either level).
        ta = prof.ta_tee;
        break;
      }
    }
  }
  if (!ta) {
    LOGW("teesim_cfg_resign: unknown profile '%s'", profile_id);
    return false;
  }
  // Re-sign the existing leaf exactly as patch mode does for a fresh key: keep its public key and
  // attestation content, re-root under the keybox with a patched root of trust.
  TsCreationResult* res = nullptr;
  int32_t rc = teesim_km_patch_attestation(ta.get(), leaf, leaf_len, &res);
  if (rc != 0) {
    LOGW("teesim_cfg_resign: patch_attestation failed rc=%d(%s) for profile '%s'", rc,
         teesim_km_err_name(rc), profile_id);
    return false;
  }
  size_t n = teesim_km_result_num_certs(res);
  for (size_t i = 0; i < n; ++i) {
    const uint8_t* c = nullptr;
    size_t clen = 0;
    teesim_km_result_cert(res, i, &c, &clen);
    sink(ctx, c, clen);
  }
  teesim_km_free_result(res);
  return true;
}


extern "C" bool teesim_cfg_reissue(const char* profile_id, const uint8_t* leaf, size_t leaf_len,
                                   TsCertSink sink, void* ctx) {
  if (!profile_id || !leaf || leaf_len == 0 || !sink) return false;
  LOGI("teesim_cfg_reissue: hardware certificate for profile '%s' (%zu bytes)",
       profile_id, leaf_len);
  TaPtr ta;
  {
    std::lock_guard<std::mutex> lk(g_cfg_mu);
    for (const auto& prof : g_profiles) {
      if (prof.id == profile_id) {
        // Certificate reissue is level-independent: the certificate keeps the hardware key's public
        // half, while this TA contributes only the profile keybox signer. No business private key is
        // imported into TES.
        ta = prof.ta_tee;
        break;
      }
    }
  }
  if (!ta) {
    LOGW("teesim_cfg_reissue: unknown profile '%s'", profile_id);
    return false;
  }

  TsCreationResult* res = nullptr;
  int32_t rc = teesim_km_reissue_certificate(ta.get(), leaf, leaf_len, &res);
  if (rc != 0) {
    LOGW("teesim_cfg_reissue: reissue failed rc=%d(%s) for profile '%s'",
         rc, teesim_km_err_name(rc), profile_id);
    return false;
  }
  const size_t n = teesim_km_result_num_certs(res);
  for (size_t i = 0; i < n; ++i) {
    const uint8_t* c = nullptr;
    size_t clen = 0;
    teesim_km_result_cert(res, i, &c, &clen);
    sink(ctx, c, clen);
  }
  teesim_km_free_result(res);
  LOGI("teesim_cfg_reissue: emitted %zu-cert chain for profile '%s'", n, profile_id);
  return true;
}


extern "C" bool teesim_cfg_reissue_for_hardware_uid(int32_t uid, const uint8_t* leaf,
                                                     size_t leaf_len, TsCertSink sink, void* ctx) {
  if (uid < 0 || !leaf || leaf_len == 0 || !sink) return false;

  // Copy only the stable profile id while holding the routing lock, then use the ordinary reissue
  // path after releasing it. teesim_cfg_reissue takes the same lock to retain the live TA, so
  // calling it while g_cfg_mu is held would deadlock.
  std::string profile_id;
  {
    std::lock_guard<std::mutex> lk(g_cfg_mu);
    for (const auto& prof : g_profiles) {
      if (!prof.hardware_mode) continue;
      if (std::find(prof.uids.begin(), prof.uids.end(), uid) == prof.uids.end()) continue;
      profile_id = prof.id;
      break;
    }
  }
  if (profile_id.empty()) {
    LOGW("teesim_cfg_reissue_for_hardware_uid: uid=%d is not owned by a strict hardware profile",
         uid);
    return false;
  }
  return teesim_cfg_reissue(profile_id.c_str(), leaf, leaf_len, sink, ctx);
}

// Create a local device wrapping the real HAL binder (may be null). Returns an
// AIBinder* whose ownership passes to the caller (release with AIBinder_decStrong).
//
// `security_level` is a legacy caller hint only. Hardware identity is derived here from the wrapped
// HAL's own getHardwareInfo() or a canonical service binder; an unproven hint is never used to
// manufacture TEE/StrongBox. We report StrongBox only when a
// real StrongBox HAL exists. This runs once per proxy (the caller caches the
// result), and the ForwardGuard keeps this getHardwareInfo from looping back
// through the interceptor. Any failure leaves the passed fallback in place.
extern "C" AIBinder* teesim_router_new_device(int32_t security_level, AIBinder* real_binder) {
  if (!real_binder) {
    LOGW("teesim_router_new_device: no real KeyMint binder; refusing to construct a synthetic "
         "TEE/StrongBox proxy");
    return nullptr;
  }

  ndk::SpAIBinder sp(real_binder);
  AIBinder_incStrong(real_binder);  // keep our own reference
  std::shared_ptr<IKeyMintDevice> real = IKeyMintDevice::fromBinder(sp);
  if (!real) {
    LOGW("teesim_router_new_device: binder descriptor looked like IKeyMintDevice but fromBinder "
         "failed; leaving the original backend untouched rather than guessing a hardware level");
    return nullptr;
  }

  {
    ForwardGuard g;
    SecurityLevel registered_level = SecurityLevel::SOFTWARE;
    std::string registered_service;
    const bool registered =
        RegisteredServiceLevel(real_binder, &registered_level, &registered_service);
    KeyMintHardwareInfo hw;
    if (real->getHardwareInfo(&hw).isOk()) {
      SecurityLevel reported = hw.securityLevel;
      if (registered) {
        if (reported != registered_level) {
          LOGW("teesim_router_new_device: registered KeyMint instance is %s but hardware info "
               "reports %s ('%s'/'%s'); canonical binder identity wins",
               LevelName(registered_level), LevelName(reported), hw.keyMintName.c_str(),
               hw.keyMintAuthorName.c_str());
        } else {
          LOGI("teesim_router_new_device: binder service identity confirms %s ('%s'/'%s')",
               LevelName(registered_level), hw.keyMintName.c_str(), hw.keyMintAuthorName.c_str());
        }
        reported = registered_level;
      }
      // Without a canonical service identity, trust the HAL's explicit SecurityLevel exactly.
      // Vendor/author strings are diagnostics only; "NXP" or "strongbox" in a name is not proof of
      // a StrongBox security domain.
      security_level = static_cast<int32_t>(reported);
    } else if (registered) {
      // Even when getHardwareInfo is temporarily broken, a binder fetched from the canonical
      // /default or /strongbox service name still has an unambiguous level.
      security_level = static_cast<int32_t>(registered_level);
      LOGW("teesim_router_new_device: getHardwareInfo failed; using canonical binder service "
           "identity=%s", LevelName(registered_level));
    } else {
      LOGW("teesim_router_new_device: getHardwareInfo failed and binder has no canonical "
           "TEE/StrongBox identity; leaving original KeyMint path untouched");
      return nullptr;
    }
  }
  std::string hw_name;
  std::string hw_author;
  if (real) {
    ForwardGuard g;
    KeyMintHardwareInfo hw;
    if (real->getHardwareInfo(&hw).isOk()) {
      hw_name = hw.keyMintName;
      hw_author = hw.keyMintAuthorName;
    }
  }

  // Never wrap a SOFTWARE-level KeyMint. keystore2 serves SecurityLevel::SOFTWARE from an in-process
  // km_compat device on every device — native TEE devices included (only TrustedEnvironment and
  // StrongBox resolve to a native HAL; SOFTWARE always takes the compat fallback). We only simulate the
  // hardware levels; wrapping the software leg would route a target uid's ordinary software keys (via
  // ProfileForRequest's uid fallback) into the TA, so we bail here: LocalFor caches this nullptr and
  // HookedTransact falls through to real_transact, leaving the software path untouched. The early
  // return is ref-balanced — `real` releases its fromBinder reference as it goes out of scope,
  // restoring real_binder to exactly the count keystore2 holds; adding a decStrong here would
  // under-reference it.
  if (static_cast<SecurityLevel>(security_level) == SecurityLevel::SOFTWARE) {
    LOGI("teesim_router_new_device: SOFTWARE-level KeyMint (real=%p, remote=%d); NOT wrapping",
         real_binder, real_binder ? AIBinder_isRemote(real_binder) : -1);
    return nullptr;
  }
  // keystore2 resolves a distinct IKeyMintDevice for TrustedEnvironment (level 1) and, when present,
  // StrongBox (level 2); each is wrapped by its own local device at its real level. remote=0 marks a
  // legacy km_compat leg, remote=1 a native HAL.
  const SecurityLevel resolved_level = static_cast<SecurityLevel>(security_level);
  const bool remote = real_binder ? AIBinder_isRemote(real_binder) : false;
  std::string canonical_service;
  SecurityLevel canonical_level = SecurityLevel::SOFTWARE;
  const bool canonical =
      RegisteredServiceLevel(real_binder, &canonical_level, &canonical_service) &&
      canonical_level == resolved_level;

  auto domain = MakeBackendDomain(resolved_level, std::move(real), canonical_service, canonical,
                                  remote, hw_name, hw_author);
  ReplayBackendLifecycleState(domain);
  LOGI("teesim_router_new_device: backend domain=%s#%llu service=%s remote=%d canonical=%d "
       "hal='%s'/'%s' sharedsecret=%s secureclock=%s rkp=%s",
       domain->Label(), static_cast<unsigned long long>(domain->epoch),
       domain->keymint_service.empty() ? "<compat/unknown>" : domain->keymint_service.c_str(),
       domain->remote, domain->canonical_identity, domain->keymint_name.c_str(),
       domain->keymint_author.c_str(),
       domain->shared_secret_service.empty() ? "<none>" : domain->shared_secret_service.c_str(),
       domain->secure_clock_service.empty() ? "<none>" : domain->secure_clock_service.c_str(),
       domain->rkp_instance.empty() ? "<none>" : domain->rkp_instance.c_str());
  auto dev = ndk::SharedRefBase::make<TeesimKeyMintDevice>(std::move(domain));
  ndk::SpAIBinder b = dev->asBinder();
  AIBinder* raw = b.get();
  AIBinder_incStrong(raw);
  return raw;
}
