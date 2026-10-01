// The interceptor's side of the KeyMint hook, as the router sees it.
//
// Both definitions live in keymint_hook.cpp, in the same shared object as the router, so a
// signature that drifted between the two would link cleanly and misbehave at runtime. One header,
// included by both, makes a drift a compile error instead.
#ifndef TEESIM_KEYMINT_HOOK_H
#define TEESIM_KEYMINT_HOOK_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Set by the router around calls into the real HAL so the interceptor lets those transactions
// through instead of looping back to us.
void teesim_hook_set_forwarding(bool forwarding);

// What the RKP gate decided for the request this thread is serving.
//
// keystore2 resolves the attest key on the app's own binder thread before calling generateKey, so
// the router prints this on its generateKey line to say whether an attest key it is about to
// forward got past the gate, and which way.
typedef struct {
  // "denied" | "allowed-not-target" | "allowed-rkp-only-level" |
  // "allowed-hardware-mode" | "allowed-hardware-inline" | "allowed-hardware-unbound" | "none".
  const char *verdict;
  int32_t uid;      // the uid the gate saw, or -1
  uint32_t rid;     // the request id the gate's own log line carried, or 0
  uint32_t age_ms;  // how long ago the verdict was recorded, in milliseconds
} TsRkpVerdict;

// Take this thread's verdict, clearing it. Clearing matters: a verdict armed for a request
// keystore2 then abandoned would otherwise be reported on the next app's generateKey. `age_ms` is
// what distinguishes the two — a verdict from milliseconds ago belongs to the request in hand, one
// from seconds ago does not.
void teesim_hook_take_rkp_verdict(TsRkpVerdict *out);

// Snapshot of the concrete real-hardware backend currently bound to one KeyMint security level.
// Strings are copied into fixed buffers so the hook never keeps pointers into router-owned state.
#define TS_BACKEND_SERVICE_MAX 128
#define TS_BACKEND_INSTANCE_MAX 32
typedef struct {
  int32_t present;             // 1 when a live backend domain is registered
  int32_t security_level;      // AIDL SecurityLevel ordinal
  int32_t canonical_identity;  // matched /default or /strongbox binder identity
  int32_t remote;              // backend KeyMint binder is remote
  uint64_t epoch;              // increments whenever keystore2 resolves a new backend binder
  char keymint_service[TS_BACKEND_SERVICE_MAX];
  char rkp_instance[TS_BACKEND_INSTANCE_MAX];
} TsBackendDomainSnapshot;

// Returns true and fills the snapshot when a live domain exists for security_level.
bool teesim_backend_domain_snapshot(int32_t security_level, TsBackendDomainSnapshot *out);

#ifdef __cplusplus
}
#endif

#endif  // TEESIM_KEYMINT_HOOK_H
