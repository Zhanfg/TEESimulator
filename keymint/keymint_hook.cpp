// Interceptor that redirects keystore2's KeyMint transactions to our local
// binder.
//
// keystore2 resolves and caches the KeyMint proxy at boot, before we are
// injected, so we cannot redirect at resolution time. Instead we PLT-hook
// AIBinder_transact: for a transaction on the real KeyMint proxy whose code is
// one we handle, we copy the request into a parcel bound to our local binder and
// dispatch it there. The local binder itself decides, per request, whether to
// simulate or forward to the real HAL, so this hook is deliberately dumb.

#include <aidl/android/hardware/security/keymint/IKeyMintDevice.h>
#include <aidl/android/security/rkp/BnGetKeyCallback.h>
#include <aidl/android/security/rkp/BnGetRegistrationCallback.h>
#include <aidl/android/security/rkp/BnRegistration.h>
#include <aidl/android/security/rkp/IGetKeyCallback.h>
#include <aidl/android/security/rkp/IGetRegistrationCallback.h>
#include <aidl/android/security/rkp/IRegistration.h>
#include <aidl/android/security/rkp/IRemoteProvisioning.h>
#include <aidl/android/security/rkp/IStoreUpgradedKeyCallback.h>
#include <aidl/android/security/rkp/RemotelyProvisionedKey.h>
#include <android/binder_ibinder.h>
#include <android/binder_parcel.h>
#include <android/binder_status.h>

#include <sys/system_properties.h>
#include <time.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

// The subsystem every line from this file is stamped with; see injector/include/logging.hpp.
#define LOG_SUB "km/hook"
#include "control.h"
#include "keymint_hook.h"
#include "logging.hpp"
#include "lsplt.hpp"

using aidl::android::hardware::security::keymint::IKeyMintDevice;
using aidl::android::security::rkp::BnGetKeyCallback;
using aidl::android::security::rkp::BnGetRegistrationCallback;
using aidl::android::security::rkp::BnRegistration;
using aidl::android::security::rkp::IGetKeyCallback;
using aidl::android::security::rkp::IGetRegistrationCallback;
using aidl::android::security::rkp::IRegistration;
using aidl::android::security::rkp::IRemoteProvisioning;
using aidl::android::security::rkp::IStoreUpgradedKeyCallback;
using aidl::android::security::rkp::RemotelyProvisionedKey;

// Implemented in keymint_router.cpp.
extern "C" AIBinder* teesim_router_new_device(int32_t security_level, AIBinder* real_binder);
// True if the calling uid belongs to a live target profile (keymint_router.cpp).
extern "C" bool teesim_is_target_uid(int32_t uid);
// 0 not targeted, 1 compatibility profile (RKP gate may deny), 2 strict hardware profile (never deny).
extern "C" int teesim_target_rkp_policy(int32_t uid);
// Reissue only the certificate of an inline hardware RKP key for the strict-hardware profile
// owning keyId/uid. The opaque hardware key blob never crosses this API.
extern "C" bool teesim_cfg_reissue_for_hardware_uid(int32_t uid, const uint8_t* leaf,
                                                      size_t leaf_len, TsCertSink sink, void* ctx);

namespace {

binder_status_t (*real_transact)(AIBinder*, transaction_code_t, AParcel**, AParcel**,
                                 binder_flags_t) = nullptr;

// Marks the current thread as forwarding into the real HAL, so we let those
// transactions pass straight through.
thread_local bool tls_forwarding = false;

std::mutex g_mu;
// Real KeyMint proxy -> our local device wrapping it. A nullptr value is a NEGATIVE cache ("do not
// wrap this proxy", i.e. a SOFTWARE-level km_compat device) so we neither re-probe its
// getHardwareInfo nor rebuild a device on every transact. Keyed on the raw proxy pointer, which is
// safe because keystore2 caches its per-level KeyMint devices for the process lifetime, so the
// pointer is stable and never reallocated (the negative cache relies on this too).
std::map<AIBinder*, AIBinder*> g_local_for_proxy;

// Our own local devices (the non-null values of g_local_for_proxy). IsKeyMintProxy matches any local
// IKeyMintDevice by descriptor, and our own TeesimKeyMintDevice is one, so IsKeyMintProxy excludes
// anything in this set. (Redirect dispatches our device through real_transact — the unhooked LSPlt
// backup — so it never re-enters the hook; forwarding recursion is prevented by tls_forwarding, not
// this set. This is a guard against any other caller transacting our device through the hooked symbol.)
//
// Guarded by a SEPARATE mutex, not g_mu: LocalFor holds g_mu across teesim_router_new_device, which
// makes a blocking getHardwareInfo IPC into the real HAL, while IsOurDevice runs on the transact hot
// path — one shared lock would stall every handled transact behind device construction. Lock order is
// always g_mu -> g_our_mu (IsOurDevice takes g_our_mu alone; LocalFor takes g_mu, then g_our_mu).
std::mutex g_our_mu;
std::set<AIBinder*> g_our_devices;

// True if `binder` is a TeesimKeyMintDevice we created.
bool IsOurDevice(AIBinder* binder) {
  std::lock_guard<std::mutex> lk(g_our_mu);
  return g_our_devices.count(binder) != 0;
}

bool IsHandled(transaction_code_t code) {
  // Stable-AIDL transaction codes (FIRST_CALL_TRANSACTION=1). Besides the key ownership/operation
  // calls, lifecycle signals must pass through the typed local proxy so TES can replay them into a
  // newly-resolved hardware backend after binder death. Strict hardware still forwards the actual
  // signal to the genuine HAL; TES only latches the monotonic state.
  switch (code) {
    case 3:   // generateKey
    case 4:   // importKey
    case 5:   // importWrappedKey
    case 6:   // upgradeKey
    case 7:   // deleteKey
    case 10:  // begin
    case 11:  // deviceLocked
    case 12:  // earlyBootEnded
    case 13:  // convertStorageKeyToEphemeral
    case 14:  // getKeyCharacteristics
    case 18:  // setAdditionalAttestationInfo
      return true;
    default:
      return false;
  }
}

// Identity check for the KeyMint binder keystore2 transacts. We match on the class descriptor alone
// and do not require AIBinder_isRemote, so we catch KeyMint whether it is remote or in-process:
//
//   - Native KeyMint HAL: keystore2's TrustedEnvironment/StrongBox proxy is a remote binder.
//   - Legacy Keymaster (keymaster@4.x) backend: keystore2 has no native KeyMint, so per security level
//     it holds an in-process km_compat IKeyMintDevice (getKeyMintDevice) — stored directly (keymaster
//     4.0/4.1) or behind a BacklevelKeyMintWrapper (downlevel). Either way the binder that reaches
//     AIBinder_transact is a local proxy (isRemote==false).
//
// The SOFTWARE level is excluded by level, not here: keystore2 serves SecurityLevel::SOFTWARE from an
// in-process km_compat device on every device, and teesim_router_new_device returns nullptr for it
// (LocalFor caches that), so the software leg is never wrapped. See that function.
//
// The descriptor also matches our own local TeesimKeyMintDevice, so we exclude it (IsOurDevice). The
// descriptor is compared first, so the g_our_mu lookup runs only for actual IKeyMintDevice binders.
bool IsKeyMintProxy(AIBinder* binder) {
  const AIBinder_Class* clazz = AIBinder_getClass(binder);
  if (!clazz) return false;
  const char* desc = AIBinder_Class_getDescriptor(clazz);
  if (!desc || std::strcmp(desc, IKeyMintDevice::descriptor) != 0) return false;
  return !IsOurDevice(binder);
}

// What the RKP gate below decided on this thread, and for which uid. keystore2 resolves the
// remote-provisioning key on the app's own binder thread while it is still serving that app's
// generateKey, so the router can read this back and state, on the generateKey line itself, why the
// request did or did not arrive carrying a real attest key. "none" means the gate never ran on this
// thread — which is the answer whenever a request turns up with an attest key we never saw fetched.
thread_local const char* tls_rkp_verdict = "none";
thread_local int32_t tls_rkp_uid = -1;
// The request id the gate's own line carried, and when the verdict was recorded, so the router can
// say both which line this verdict came from and whether it is fresh enough to belong to the
// request in hand.
thread_local uint32_t tls_rkp_rid = 0;
thread_local uint64_t tls_rkp_at_ms = 0;

uint64_t NowMonoMs() {
  struct timespec ts{};
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return static_cast<uint64_t>(ts.tv_sec) * 1000u + static_cast<uint64_t>(ts.tv_nsec) / 1000000u;
}

// The framework RKP front-end keystore2 asks for a remote-provisioned attestation key. keystore2
// resolves it by calling IRemoteProvisioning.getRegistration on this binder; failing that transact
// makes keystore2 fall back to "no attest key" (get_attest_key_info -> Ok(None)) on a hybrid device,
// so it appends no real-hardware certificate chain to the key we mint.
bool IsRkpProvisioning(AIBinder* binder) {
  if (!AIBinder_isRemote(binder)) return false;
  const AIBinder_Class* clazz = AIBinder_getClass(binder);
  if (!clazz) return false;
  const char* desc = AIBinder_Class_getDescriptor(clazz);
  return desc && std::strcmp(desc, "android.security.rkp.IRemoteProvisioning") == 0;
}

// Read a security level's rkp_only property. Fills `raw` with the property's current value (empty
// string if unset) so our RKP-policy logging can report exactly what keystore2 and this guard see at
// decision time, and returns whether it is set to a truthy value ("true"/"1"). On such a level
// keystore2 has no batch key to fall back to, so denying its RKP lookup makes generateKey fail
// outright (get_attest_key_info returns Err instead of Ok(None)); there we must let the lookup
// through. We only ever READ the property — a global write would be an obvious detection point.
bool ReadRkpOnly(const char* name, char raw[PROP_VALUE_MAX]) {
  raw[0] = '\0';
  int n = __system_property_get(name, raw);
  return n > 0 && (std::strcmp(raw, "true") == 0 || std::strcmp(raw, "1") == 0);
}

// Log the device's remote-key-provisioning policy once, at install. These are the properties that
// decide whether our per-target RKP denial is safe: the two per-level rkp_only knobs keystore2 reads
// to pick its attestation-key source, plus enable_rkpd (whether the rkpd provisioner runs at all).
// Dumping the ground truth once makes every deny/NOT-denying decision below self-explanatory in a
// bug report — a reader can see what the guard is reacting to without guessing at the device state.
void LogRkpPolicySnapshot() {
  static const char* const kProps[] = {
      "remote_provisioning.tee.rkp_only",
      "remote_provisioning.strongbox.rkp_only",
      // AOSP/device_config-backed builds commonly expose this persistent knob.
      "persist.device_config.remote_key_provisioning_native.enable_rkpd",
      // ColorOS/OxygenOS and some vendor stacks expose the effective RKP state here instead.
      // It is informational for our policy: we never write it, but logging it makes an otherwise
      // invisible "RKP is enabled but the WebUI shows nothing" device immediately diagnosable.
      "remote_provisioning.enable_rkpd",
  };
  for (const char* name : kProps) {
    char buf[PROP_VALUE_MAX] = {0};
    int n = __system_property_get(name, buf);
    LOGI("LogRkpPolicySnapshot: %s=%s", name, n > 0 ? buf : "<unset>");
  }
}

// Allocator for AParcel_readString: `length` includes the null terminator, or is -1 for a null string.
bool RkpStringAllocator(void* string_data, int32_t length, char** buffer) {
  char** out = static_cast<char**>(string_data);
  if (length < 0) {
    *out = nullptr;
    *buffer = nullptr;
    return true;
  }
  *out = static_cast<char*>(malloc(length));
  if (*out == nullptr) return false;
  *buffer = *out;
  return true;
}

// The instance part of an IRemotelyProvisionedComponent name. keystore2 asks for the
// interface-qualified instance its globals build for the security level —
// "android.hardware.security.keymint.IRemotelyProvisionedComponent/strongbox", never a bare
// "strongbox" — so the instance is whatever follows the last '/'.
const char* IrpcInstance(const char* name) {
  const char* slash = std::strrchr(name, '/');
  return slash ? slash + 1 : name;
}

// Extract the first DER object from RKPD's concatenated X.509 chain. CertificateFactory accepts a
// sequence of DER certificates with no outer container, so the first object is exactly the ATTEST_KEY
// leaf we must reissue. This parser touches only the DER tag/length envelope; Rust/BoringSSL validates
// the actual X.509 certificate in teesim_cfg_reissue.
bool FirstDerCertificate(const std::vector<uint8_t>& chain, const uint8_t** leaf, size_t* leaf_len) {
  if (!leaf || !leaf_len || chain.size() < 2 || chain[0] != 0x30) return false;
  size_t header = 2;
  size_t body = 0;
  const uint8_t first_len = chain[1];
  if ((first_len & 0x80u) == 0) {
    body = first_len;
  } else {
    const size_t n = first_len & 0x7fu;
    if (n == 0 || n > sizeof(size_t) || 2 + n > chain.size()) return false;  // no indefinite DER
    header += n;
    for (size_t i = 0; i < n; ++i) {
      if (body > (SIZE_MAX >> 8)) return false;
      body = (body << 8) | chain[2 + i];
    }
  }
  if (body > chain.size() - header) return false;
  *leaf = chain.data();
  *leaf_len = header + body;
  return true;
}

struct InlineRkpState {
  std::mutex mu;
  // Original keystore2 callback binder -> callback wrapper handed to RKPD. Keeping the wrapper alive
  // is required until RKPD emits onSuccess/onCancel/onError; cancelGetKey looks it up here.
  std::map<AIBinder*, std::shared_ptr<IGetKeyCallback>> callbacks;
};

class InlineRkpGetKeyCallback final : public BnGetKeyCallback {
 public:
  InlineRkpGetKeyCallback(std::shared_ptr<IGetKeyCallback> original, int32_t key_id,
                          bool strongbox, std::shared_ptr<InlineRkpState> state)
      : original_(std::move(original)),
        key_id_(key_id),
        strongbox_(strongbox),
        state_(std::move(state)) {
    if (original_) original_binder_ = original_->asBinder().get();
  }

  ndk::ScopedAStatus onSuccess(const RemotelyProvisionedKey& key) override {
    RemotelyProvisionedKey out = key;  // keyBlob copied byte-for-byte and never reassigned below.

    const uint8_t* leaf = nullptr;
    size_t leaf_len = 0;
    if (FirstDerCertificate(key.encodedCertChain, &leaf, &leaf_len)) {
      std::vector<uint8_t> reissued;
      auto sink = [](void* ctx, const uint8_t* der, size_t len) {
        auto* bytes = static_cast<std::vector<uint8_t>*>(ctx);
        bytes->insert(bytes->end(), der, der + len);
      };
      if (teesim_cfg_reissue_for_hardware_uid(key_id_, leaf, leaf_len, sink, &reissued) &&
          !reissued.empty()) {
        out.encodedCertChain = std::move(reissued);
        LOGI("inline RKP: re-rooted %s ATTEST_KEY certificate for uid=%d "
             "(keyBlob=%zu bytes unchanged, chain %zu -> %zu bytes)",
             strongbox_ ? "StrongBox" : "TEE", key_id_, key.keyBlob.size(),
             key.encodedCertChain.size(), out.encodedCertChain.size());
      } else {
        LOGW("inline RKP: certificate reissue failed for strict hardware uid=%d; preserving the "
             "original hardware key and RKPD chain", key_id_);
      }
    } else {
      LOGW("inline RKP: malformed/empty certificate chain for strict hardware uid=%d; preserving "
           "the original hardware key and chain", key_id_);
    }

    // This invariant is intentionally explicit: the whole point of the inline hook is certificate
    // replacement WITHOUT key migration.
    if (out.keyBlob != key.keyBlob) {
      LOGE("inline RKP: invariant violation: keyBlob changed while reissuing uid=%d; refusing "
           "modified result", key_id_);
      out = key;
    }

    auto st = original_ ? original_->onSuccess(out)
                        : ndk::ScopedAStatus::fromExceptionCode(EX_NULL_POINTER);
    Done();
    return st;
  }

  ndk::ScopedAStatus onCancel() override {
    auto st = original_ ? original_->onCancel()
                        : ndk::ScopedAStatus::fromExceptionCode(EX_NULL_POINTER);
    Done();
    return st;
  }

  ndk::ScopedAStatus onError(IGetKeyCallback::ErrorCode error,
                             const std::string& description) override {
    auto st = original_ ? original_->onError(error, description)
                        : ndk::ScopedAStatus::fromExceptionCode(EX_NULL_POINTER);
    Done();
    return st;
  }

 private:
  void Done() {
    if (!state_ || !original_binder_) return;
    std::lock_guard<std::mutex> lk(state_->mu);
    state_->callbacks.erase(original_binder_);
  }

  std::shared_ptr<IGetKeyCallback> original_;
  int32_t key_id_;
  bool strongbox_;
  std::shared_ptr<InlineRkpState> state_;
  AIBinder* original_binder_ = nullptr;
};

class InlineRkpRegistration final : public BnRegistration {
 public:
  InlineRkpRegistration(std::shared_ptr<IRegistration> real, bool strongbox)
      : real_(std::move(real)), strongbox_(strongbox), state_(std::make_shared<InlineRkpState>()) {}

  ndk::ScopedAStatus getKey(int32_t key_id,
                            const std::shared_ptr<IGetKeyCallback>& callback) override {
    if (!real_) return ndk::ScopedAStatus::fromExceptionCode(EX_NULL_POINTER);

    // keyId is the application uid in keystore2. Re-evaluate live routing here instead of trusting
    // the uid that happened to request getRegistration: config may have reloaded while RKPD was
    // provisioning, and this guarantees certificate rewriting never widens beyond strict hardware.
    if (teesim_target_rkp_policy(key_id) != 2 || !callback) {
      return real_->getKey(key_id, callback);
    }

    auto wrapped = ndk::SharedRefBase::make<InlineRkpGetKeyCallback>(
        callback, key_id, strongbox_, state_);
    AIBinder* original_binder = callback->asBinder().get();
    {
      std::lock_guard<std::mutex> lk(state_->mu);
      state_->callbacks[original_binder] = wrapped;
    }

    auto st = real_->getKey(key_id, wrapped);
    if (!st.isOk()) {
      std::lock_guard<std::mutex> lk(state_->mu);
      state_->callbacks.erase(original_binder);
      LOGW("inline RKP: real %s getKey(uid=%d) failed before callback: exception=%d status=%d",
           strongbox_ ? "StrongBox" : "TEE", key_id, st.getExceptionCode(), st.getStatus());
    }
    return st;
  }

  ndk::ScopedAStatus cancelGetKey(const std::shared_ptr<IGetKeyCallback>& callback) override {
    if (!real_) return ndk::ScopedAStatus::fromExceptionCode(EX_NULL_POINTER);
    if (!callback) return real_->cancelGetKey(callback);

    std::shared_ptr<IGetKeyCallback> forwarded = callback;
    AIBinder* original_binder = callback->asBinder().get();
    {
      std::lock_guard<std::mutex> lk(state_->mu);
      auto it = state_->callbacks.find(original_binder);
      if (it != state_->callbacks.end()) forwarded = it->second;
    }
    return real_->cancelGetKey(forwarded);
  }

  ndk::ScopedAStatus storeUpgradedKeyAsync(
      const std::vector<uint8_t>& old_key_blob, const std::vector<uint8_t>& new_key_blob,
      const std::shared_ptr<IStoreUpgradedKeyCallback>& callback) override {
    // Upgrade belongs entirely to RKPD/IRPC. Do not inspect or rewrite either opaque hardware blob.
    return real_ ? real_->storeUpgradedKeyAsync(old_key_blob, new_key_blob, callback)
                 : ndk::ScopedAStatus::fromExceptionCode(EX_NULL_POINTER);
  }

 private:
  std::shared_ptr<IRegistration> real_;
  bool strongbox_;
  std::shared_ptr<InlineRkpState> state_;
};

class InlineRkpRegistrationCallback final : public BnGetRegistrationCallback {
 public:
  InlineRkpRegistrationCallback(std::shared_ptr<IGetRegistrationCallback> original, bool strongbox)
      : original_(std::move(original)), strongbox_(strongbox) {}

  ndk::ScopedAStatus onSuccess(const std::shared_ptr<IRegistration>& registration) override {
    if (!original_) return ndk::ScopedAStatus::fromExceptionCode(EX_NULL_POINTER);
    if (!registration) return original_->onSuccess(registration);

    auto wrapped = ndk::SharedRefBase::make<InlineRkpRegistration>(registration, strongbox_);
    LOGD("inline RKP: wrapped %s IRegistration for strict hardware certificate reissue",
         strongbox_ ? "StrongBox" : "TEE");
    return original_->onSuccess(wrapped);
  }

  ndk::ScopedAStatus onCancel() override {
    return original_ ? original_->onCancel()
                     : ndk::ScopedAStatus::fromExceptionCode(EX_NULL_POINTER);
  }

  ndk::ScopedAStatus onError(const std::string& error) override {
    return original_ ? original_->onError(error)
                     : ndk::ScopedAStatus::fromExceptionCode(EX_NULL_POINTER);
  }

 private:
  std::shared_ptr<IGetRegistrationCallback> original_;
  bool strongbox_;
};

// Read getRegistration(String, IGetRegistrationCallback) without hard-coding Binder header size.
// The input parcel is restored before return so falling back to the original transaction is safe.
bool ReadRkpRegistrationArgs(AIBinder* binder, AParcel* in, std::string* irpc_name,
                             std::shared_ptr<IGetRegistrationCallback>* callback) {
  if (!binder || !in || !irpc_name || !callback) return false;

  AParcel* probe = nullptr;
  if (AIBinder_prepareTransaction(binder, &probe) != STATUS_OK) return false;
  const int32_t header = AParcel_getDataSize(probe);
  AParcel_delete(probe);

  const int32_t saved = AParcel_getDataPosition(in);
  if (AParcel_setDataPosition(in, header) != STATUS_OK) return false;

  char* name = nullptr;
  AIBinder* callback_binder = nullptr;
  bool ok = AParcel_readString(in, &name, RkpStringAllocator) == STATUS_OK && name != nullptr &&
            AParcel_readStrongBinder(in, &callback_binder) == STATUS_OK && callback_binder != nullptr;

  AParcel_setDataPosition(in, saved);
  if (!ok) {
    free(name);
    if (callback_binder) AIBinder_decStrong(callback_binder);
    return false;
  }

  irpc_name->assign(name);
  free(name);

  // AParcel_readStrongBinder transfers one strong reference to us; SpAIBinder adopts it.
  ndk::SpAIBinder cb_binder(callback_binder);
  *callback = IGetRegistrationCallback::fromBinder(cb_binder);
  return static_cast<bool>(*callback);
}

// Replace keystore2's registration callback for a strict-hardware request, so the registration it
// receives is our transparent wrapper. We make a fresh typed getRegistration call rather than
// rewriting raw parcel bytes; tls_forwarding ensures that call goes directly to RKPD and cannot loop
// back through this hook. The original oneway input parcel is consumed only after the replacement
// call has actually been issued.
bool RedirectHardwareRkpRegistration(AIBinder* binder, AParcel** in, AParcel** out,
                                     binder_flags_t flags, binder_status_t* result) {
  if (!binder || !in || !*in || !result) return false;

  std::string irpc_name;
  std::shared_ptr<IGetRegistrationCallback> original_callback;
  if (!ReadRkpRegistrationArgs(binder, *in, &irpc_name, &original_callback)) return false;

  const bool strongbox = std::strcmp(IrpcInstance(irpc_name.c_str()), "strongbox") == 0;

  AIBinder_incStrong(binder);
  ndk::SpAIBinder remote_binder(binder);
  auto remote = IRemoteProvisioning::fromBinder(remote_binder);
  if (!remote) return false;

  auto wrapped = ndk::SharedRefBase::make<InlineRkpRegistrationCallback>(
      original_callback, strongbox);

  const bool previous_forwarding = tls_forwarding;
  tls_forwarding = true;
  auto st = remote->getRegistration(irpc_name, wrapped);
  tls_forwarding = previous_forwarding;

  // The typed replacement owns its own parcel. We are replacing the original AIBinder_transact, so
  // consume that input exactly as AIBinder_transact would. getRegistration is oneway and has no reply.
  AParcel_delete(*in);
  *in = nullptr;
  (void)out;
  (void)flags;

  *result = st.isOk() ? STATUS_OK : st.getStatus();
  if (!st.isOk() && *result == STATUS_OK) *result = STATUS_FAILED_TRANSACTION;

  LOGD("inline RKP: typed getRegistration replacement for %s finished status=%d exception=%d",
       strongbox ? "StrongBox" : "TEE", *result, st.getExceptionCode());
  return true;
}

// Which security level a getRegistration transact targets, read from its first argument — the
// IRemotelyProvisionedComponent name, whose instance is "strongbox" for StrongBox and "default" for
// TE. The interface header size is measured from a throwaway prepared transaction on the same binder,
// so no wire format is hardcoded; the input parcel's read position is saved and restored. `irpc_name`
// receives the name as read, so a bug report shows what the decision below was actually made on.
// Defaults to TE if unreadable.
bool GetRegIsStrongBox(AIBinder* binder, AParcel* in, std::string* irpc_name) {
  AParcel* probe = nullptr;
  if (AIBinder_prepareTransaction(binder, &probe) != STATUS_OK) return false;
  int32_t header = AParcel_getDataSize(probe);  // args begin past the interface header (cf. Redirect)
  AParcel_delete(probe);

  int32_t saved = AParcel_getDataPosition(in);
  if (AParcel_setDataPosition(in, header) != STATUS_OK) return false;
  char* name = nullptr;
  bool strongbox = false;
  if (AParcel_readString(in, &name, RkpStringAllocator) == STATUS_OK && name != nullptr) {
    strongbox = std::strcmp(IrpcInstance(name), "strongbox") == 0;
    irpc_name->assign(name);
  }
  free(name);
  AParcel_setDataPosition(in, saved);
  return strongbox;
}

// Return (creating if needed) the local device that wraps `proxy`.
AIBinder* LocalFor(AIBinder* proxy) {
  std::lock_guard<std::mutex> lk(g_mu);
  auto it = g_local_for_proxy.find(proxy);
  if (it != g_local_for_proxy.end()) return it->second;
  // teesim_router_new_device derives this proxy's real security level from the
  // wrapped HAL's getHardwareInfo(); the value passed here is only the fallback
  // used if that query fails.
  AIBinder* local = teesim_router_new_device(1 /* fallback: TRUSTED_ENVIRONMENT */, proxy);
  g_local_for_proxy[proxy] = local;  // may be nullptr (SOFTWARE): negative cache, do not re-probe
  if (local) {
    // Record our device so the relaxed IsKeyMintProxy never re-wraps it. We already hold g_mu; lock
    // order is g_mu -> g_our_mu. Never insert nullptr (a SOFTWARE proxy yields local==nullptr): the
    // "g_our_devices == our real devices" invariant must hold.
    std::lock_guard<std::mutex> lk(g_our_mu);
    g_our_devices.insert(local);
  }
  return local;
}

binder_status_t Redirect(AIBinder* local, transaction_code_t code, AParcel** in, AParcel** out,
                         binder_flags_t flags, AIBinder* proxy) {
  AParcel* my_in = nullptr;
  if (AIBinder_prepareTransaction(local, &my_in) != STATUS_OK) {
    return real_transact(proxy, code, in, out, flags);
  }
  int32_t hdr = AParcel_getDataSize(my_in);
  int32_t total = AParcel_getDataSize(*in);
  if (total < hdr || AParcel_appendFrom(*in, my_in, hdr, total - hdr) != STATUS_OK) {
    AParcel_delete(my_in);
    return real_transact(proxy, code, in, out, flags);
  }
  binder_status_t r = real_transact(local, code, &my_in, out, flags);  // consumes my_in
  AParcel_delete(*in);  // match AIBinder_transact's ownership contract
  *in = nullptr;
  return r;
}

binder_status_t HookedTransact(AIBinder* binder, transaction_code_t code, AParcel** in,
                               AParcel** out, binder_flags_t flags) {
  if (!tls_forwarding && in && *in) {
    // Deny a target app's remote-provisioning lookup so keystore2 attaches no real attest key. The
    // RKP resolution runs on this same binder thread (a current-thread tokio runtime block_on), while
    // keystore2 is still serving the app's generateKey, so getCallingUid is the app's uid. The gate is
    // per security level: keystore2 reads .tee.rkp_only for a TE request and .strongbox.rkp_only for a
    // StrongBox one, and denying an rkp-only level fails the key instead of falling back — so pick the
    // property matching this getRegistration's target (its irpcName) rather than the TEE one alone.
    if (IsRkpProvisioning(binder)) {
      int32_t uid = static_cast<int32_t>(AIBinder_getCallingUid());
      // The gate runs on the app's binder thread but outside any hooked entry point, so it stamps
      // its own context; the rid it records ties the verdict back to the line that made it.
      char rkp_ctx[64];
      tls_rkp_rid = teesim_log_new_rid();
      snprintf(rkp_ctx, sizeof(rkp_ctx), "[%d r%04x] ", uid, tls_rkp_rid);
      LogContext lc_(rkp_ctx);
      tls_rkp_uid = uid;
      tls_rkp_at_ms = NowMonoMs();
      const int target_policy = teesim_target_rkp_policy(uid);
      if (target_policy == 0) {
        // Not a target *at this instant*: either the app really is out of scope, or the scope is
        // stale (a reinstall gave it a new uid and no re-resolve has run yet), or the lookup did not
        // arrive on the app's binder thread and this uid is not the app's at all.
        tls_rkp_verdict = "allowed-not-target";
        LOGD("HookedTransact: RKP allowing IRemoteProvisioning transact code=%u for uid=%d (not a "
             "target uid at this moment)", code, uid);
      } else {
        std::string irpc_name;
        bool strongbox = GetRegIsStrongBox(binder, *in, &irpc_name);
        const char* prop = strongbox ? "remote_provisioning.strongbox.rkp_only"
                                      : "remote_provisioning.tee.rkp_only";
        const char* level = strongbox ? "StrongBox" : "TEE";
        const char* irpc = irpc_name.empty() ? "<unreadable>" : irpc_name.c_str();
        char raw[PROP_VALUE_MAX] = {0};
        bool rkp_only = ReadRkpOnly(prop, raw);
        const char* val = raw[0] ? raw : "<unset>";

        if (target_policy == 2) {
          // Strict hardware mode may rewrite only the public certificate chain, and only after the
          // requested IRPC instance is tied to a concrete, canonical KeyMint backend domain. The
          // first request after injection can reach RKP before keystore2 has ever transacted the
          // KeyMint binder, so "no domain yet" is normal: allow RKPD unchanged and bind on a later
          // request rather than forcing initialization or guessing.
          TsBackendDomainSnapshot backend{};
          const int32_t requested_level = strongbox ? 2 : 1;
          const char* requested_instance =
              irpc_name.empty() ? nullptr : IrpcInstance(irpc_name.c_str());
          const bool have_backend =
              requested_instance &&
              teesim_backend_domain_snapshot(requested_level, &backend) &&
              backend.present != 0;
          const bool rkp_bound =
              have_backend && backend.canonical_identity != 0 &&
              std::strcmp(backend.rkp_instance, requested_instance) == 0;

          if (!rkp_bound) {
            tls_rkp_verdict = "allowed-hardware-unbound";
            LOGW("HookedTransact: strict hardware %s RKP not yet bound to a canonical KeyMint "
                 "domain (uid=%d irpcName=%s domain_present=%d canonical=%d domain_rkp=%s); "
                 "allowing RKPD unchanged",
                 level, uid, irpc, have_backend ? 1 : 0,
                 have_backend ? backend.canonical_identity : 0,
                 have_backend && backend.rkp_instance[0] ? backend.rkp_instance : "<none>");
          } else {
            binder_status_t inline_status = STATUS_OK;
            if (RedirectHardwareRkpRegistration(binder, in, out, flags, &inline_status)) {
              tls_rkp_verdict = "allowed-hardware-inline";
              LOGI("HookedTransact: RKP wrapped %s getRegistration for strict hardware uid=%d "
                   "(domain=%s#%llu irpcName=%s, %s=%s; hardware keyBlob stays in RKPD/KeyMint)",
                   level, uid, backend.keymint_service,
                   static_cast<unsigned long long>(backend.epoch), irpc, prop, val);
              return inline_status;
            }

            tls_rkp_verdict = "allowed-hardware-mode";
            LOGW("HookedTransact: domain-bound RKP wrapper failed for strict hardware uid=%d "
                 "(domain=%s#%llu %s); allowing original registration unchanged",
                 uid, backend.keymint_service,
                 static_cast<unsigned long long>(backend.epoch), level);
          }
        } else if (rkp_only) {
          tls_rkp_verdict = "allowed-rkp-only-level";
          LOGI("HookedTransact: RKP NOT denying %s getRegistration for target uid=%d (irpcName=%s, "
               "%s=%s; denial would fail key generation on an rkp-only level)",
               level, uid, irpc, prop, val);
        } else {
          tls_rkp_verdict = "denied";
          // Compatibility patch/generation modes retain the historical gate so keystore2 does not
          // append a foreign RKP chain that the in-process TA cannot re-root.
          LOGD("HookedTransact: RKP denying %s IRemoteProvisioning transact code=%u for target uid=%d "
               "(irpcName=%s, %s=%s; compatibility profile)",
               level, code, uid, irpc, prop, val);
          AParcel_delete(*in);  // honour AIBinder_transact's ownership of the input parcel
          *in = nullptr;
          return STATUS_FAILED_TRANSACTION;  // -> Rust `?` -> get_attest_key_info Ok(None) on hybrid
        }
      }
    }
    if (IsHandled(code) && IsKeyMintProxy(binder)) {
      AIBinder* local = LocalFor(binder);
      if (local) return Redirect(local, code, in, out, flags, binder);
      // local == nullptr: a SOFTWARE-level proxy we deliberately do not wrap; fall through to
      // real_transact so keystore2's own software-key path runs untouched.
    }
  }
  return real_transact(binder, code, in, out, flags);
}

}  // namespace

extern "C" void teesim_hook_set_forwarding(bool forwarding) { tls_forwarding = forwarding; }

// The RKP gate's verdict for this thread, for the router to print on its generateKey line. Reading
// it clears it, so a later request that never reaches the gate reports "none" rather than inheriting
// the previous request's answer from the same binder thread. The age is what catches the case
// clearing cannot: a verdict armed for a request keystore2 then abandoned stays latched on the
// thread until something reads it, and only its age says it is not this request's.
extern "C" void teesim_hook_take_rkp_verdict(TsRkpVerdict* out) {
  if (!out) return;
  out->verdict = tls_rkp_verdict;
  out->uid = tls_rkp_uid;
  out->rid = tls_rkp_rid;
  out->age_ms = tls_rkp_at_ms != 0 ? static_cast<uint32_t>(NowMonoMs() - tls_rkp_at_ms) : 0;
  tls_rkp_verdict = "none";
  tls_rkp_uid = -1;
  tls_rkp_rid = 0;
  tls_rkp_at_ms = 0;
}

// Only hook real ELF modules: the main executable and shared libraries. Feeding
// LSPlt a non-ELF mapping (fonts, dex, oat, apk) makes its ELF parser fault.
bool IsHookableElf(const std::string& path, const std::string& exe) {
  if (path == exe) return true;
  if (path.size() < 3) return false;
  return path.compare(path.size() - 3, 3, ".so") == 0;
}

extern "C" bool teesim_hook_install() {
  LogRkpPolicySnapshot();  // one-shot ground truth for the RKP-denial decisions HookedTransact makes
  char exe_buf[512] = {0};
  ssize_t n = readlink("/proc/self/exe", exe_buf, sizeof(exe_buf) - 1);
  std::string exe = n > 0 ? std::string(exe_buf, n) : std::string();

  const auto maps = lsplt::MapInfo::Scan();

  // Register the AIBinder_transact hook across a chosen set of modules and commit. `exe_only`
  // limits it to the main executable; otherwise every ELF module (main exe + .so) is probed.
  auto register_and_commit = [&](bool exe_only) {
    std::set<std::pair<dev_t, ino_t>> seen;
    for (const auto& m : maps) {
      if (m.path.empty() || m.inode == 0) continue;
      if (exe_only ? (m.path != exe) : !IsHookableElf(m.path, exe)) continue;
      if (!seen.insert({m.dev, m.inode}).second) continue;
      lsplt::RegisterHook(m.dev, m.inode, "AIBinder_transact",
                          reinterpret_cast<void*>(HookedTransact),
                          reinterpret_cast<void**>(&real_transact));
    }
    // CommitHook returns false when a probed module doesn't import the symbol, which is
    // expected; success is that the caller's slot was patched (backup set).
    lsplt::CommitHook();
  };

  // The transaction we intercept — keystore2 forwarding to the real KeyMint — is issued from
  // the main executable, which is where AIBinder_transact is imported (keystore2's binder client
  // is linked into the binary). So probe just the executable's PLT first: this avoids scanning
  // (and having LSPlt warn about) every unrelated .so. Only if the importer isn't the executable
  // on some build do we widen to a full ELF scan, so coverage is never lost.
  if (!exe.empty()) {
    register_and_commit(/*exe_only=*/true);
    if (real_transact != nullptr) {
      LOGI("teesim_hook_install: AIBinder_transact patched in the main executable (%s)", exe.c_str());
      return true;
    }
  }
  register_and_commit(/*exe_only=*/false);
  LOGI("teesim_hook_install: AIBinder_transact %s after full ELF scan",
       real_transact != nullptr ? "patched" : "not found (no importer)");
  return real_transact != nullptr;
}
