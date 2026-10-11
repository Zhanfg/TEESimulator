#pragma once

// Pure policy only: no allocation, I/O, wall-clock access, or KeyMint binder work.
// A hardware-generated key without requested attestation must retain its genuine
// blob, characteristics and certificate instead of re-signing a placeholder.
// A delegated ATTEST_KEY parent intentionally retains its existing chain handling.
namespace teesim::policy {
[[nodiscard]] constexpr bool KeepHardwareResultWithoutRewrite(
    bool has_certificates, bool has_attestation_challenge, bool is_attest_key) noexcept {
  return !has_certificates || (!has_attestation_challenge && !is_attest_key);
}
}  // namespace teesim::policy
