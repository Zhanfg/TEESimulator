#ifndef TEESIM_TIMING_H
#define TEESIM_TIMING_H

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>

struct TsDelayRange {
  uint32_t min_ms = 0;
  uint32_t max_ms = 0;
};

struct TsTimingPolicy {
  TsDelayRange attestation;
  TsDelayRange operation_start;
  TsDelayRange ta_call;
};

inline TsDelayRange TsBoundedDelayRange(uint32_t min_ms, uint32_t max_ms) {
  constexpr uint32_t kMaxMs = 2000;
  min_ms = std::min(min_ms, kMaxMs);
  max_ms = std::min(max_ms, kMaxMs);
  if (min_ms > max_ms) min_ms = max_ms;
  return {min_ms, max_ms};
}

// Pure sampler used by runtime code and host tests. The entropy value is supplied by the caller
// so bounds and endpoint behaviour remain deterministic under test.
inline uint32_t TsSampleDelayMs(TsDelayRange range, uint64_t entropy) {
  range = TsBoundedDelayRange(range.min_ms, range.max_ms);
  if (range.max_ms <= range.min_ms) return range.min_ms;
  // xorshift64*: sufficient here because this is presentation jitter, never cryptographic entropy.
  uint64_t x = entropy ? entropy : 0x9e3779b97f4a7c15ULL;
  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;
  x *= 0x2545F4914F6CDD1DULL;
  const uint64_t span = static_cast<uint64_t>(range.max_ms) - range.min_ms + 1ULL;
  return range.min_ms + static_cast<uint32_t>(x % span);
}

inline uint64_t TsTimingEntropy() {
  static std::atomic<uint64_t> seq{1};
  const uint64_t now = static_cast<uint64_t>(
      std::chrono::steady_clock::now().time_since_epoch().count());
  return now ^ (seq.fetch_add(1, std::memory_order_relaxed) * 0x9e3779b97f4a7c15ULL);
}

inline uint32_t TsSleepDelay(TsDelayRange range) {
  const uint32_t ms = TsSampleDelayMs(range, TsTimingEntropy());
  if (ms != 0) std::this_thread::sleep_for(std::chrono::milliseconds(ms));
  return ms;
}

#endif  // TEESIM_TIMING_H
