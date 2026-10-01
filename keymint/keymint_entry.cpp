// Injection entry point for the KeyMint interceptor (Android 12+).
//
// The daemon injects this library into keystore2 and calls entry(). We install
// the AIBinder_transact hook in an unconfigured, forward-everything state and
// start the control server; the daemon then connects to it and pushes the
// resolved profile set. Nothing is read from disk here — the lib is a pure
// engine driven entirely by control-channel pushes.

#include "control.h"
// The subsystem every line from this file is stamped with; see injector/include/logging.hpp.
#define LOG_SUB "km"
#include "logging.hpp"

// keymint_hook.cpp
extern "C" bool teesim_hook_install();

extern "C" [[gnu::visibility("default")]] bool entry(void* /*handle*/) {
  LOGI("entry: KeyMint interceptor loading");
  if (!teesim_control_prepare()) {
    LOGE("entry: control channel setup failed before hook installation");
    return false;
  }
  bool ok = teesim_hook_install();
  if (!ok) {
    teesim_control_abort_startup();
    LOGE("entry: KeyMint interceptor hook installation failed");
    return false;
  }
  teesim_control_activate();
  LOGI("entry: KeyMint interceptor installed=1; control channel ready (awaiting config push)");
  return true;
}
