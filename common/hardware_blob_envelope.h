#pragma once

#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <vector>

namespace teesim::hwblob {

inline constexpr uint8_t kMagic[8] = {'T', 'E', 'S', 'H', 'W', 'B', 'L', 'B'};
inline constexpr uint8_t kVersion = 1;
inline constexpr size_t kHeaderSize = 16;
inline constexpr uint8_t kTrustedEnvironment = 1;
inline constexpr uint8_t kStrongBox = 2;

enum class State {
  kNone,
  kValid,
  kMalformed,
};

enum class UnwrapResult {
  kRaw,
  kUnwrapped,
  kMalformed,
  kOwnerMismatch,
};

struct Parsed {
  State state = State::kNone;
  uint8_t owner = 0;
  std::vector<uint8_t> raw;
};

inline bool ValidOwner(uint8_t owner) {
  return owner == kTrustedEnvironment || owner == kStrongBox;
}

inline uint32_t ReadBe32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) |
         (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) |
         static_cast<uint32_t>(p[3]);
}

inline void AppendBe32(std::vector<uint8_t>* out, uint32_t value) {
  out->push_back(static_cast<uint8_t>((value >> 24) & 0xff));
  out->push_back(static_cast<uint8_t>((value >> 16) & 0xff));
  out->push_back(static_cast<uint8_t>((value >> 8) & 0xff));
  out->push_back(static_cast<uint8_t>(value & 0xff));
}

inline Parsed Parse(const std::vector<uint8_t>& blob) {
  Parsed parsed;
  if (blob.size() < sizeof(kMagic) ||
      std::memcmp(blob.data(), kMagic, sizeof(kMagic)) != 0) {
    return parsed;
  }

  parsed.state = State::kMalformed;
  if (blob.size() < kHeaderSize) return parsed;
  if (blob[8] != kVersion) return parsed;
  if (blob[10] != 0 || blob[11] != 0) return parsed;
  if (!ValidOwner(blob[9])) return parsed;

  const uint32_t raw_len = ReadBe32(blob.data() + 12);
  if (raw_len == 0 ||
      static_cast<size_t>(raw_len) != blob.size() - kHeaderSize) {
    return parsed;
  }

  parsed.owner = blob[9];
  parsed.raw.assign(blob.begin() + kHeaderSize, blob.end());
  parsed.state = State::kValid;
  return parsed;
}

// Return a new versioned owner envelope. A valid envelope for the same owner is idempotent.
// A malformed/nested envelope, invalid owner or empty raw blob is rejected.
inline std::optional<std::vector<uint8_t>> Wrap(uint8_t owner,
                                                const std::vector<uint8_t>& raw) {
  if (!ValidOwner(owner) || raw.empty()) return std::nullopt;

  const Parsed existing = Parse(raw);
  if (existing.state == State::kValid) {
    if (existing.owner == owner) return raw;
    return std::nullopt;
  }
  if (existing.state == State::kMalformed) return std::nullopt;

  if (raw.size() > std::numeric_limits<uint32_t>::max()) return std::nullopt;

  std::vector<uint8_t> out;
  out.reserve(kHeaderSize + raw.size());
  out.insert(out.end(), kMagic, kMagic + sizeof(kMagic));
  out.push_back(kVersion);
  out.push_back(owner);
  out.push_back(0);
  out.push_back(0);
  AppendBe32(&out, static_cast<uint32_t>(raw.size()));
  out.insert(out.end(), raw.begin(), raw.end());
  return out;
}

// Decode an envelope for one backend owner. Historical raw blobs intentionally pass through.
inline UnwrapResult UnwrapForOwner(const std::vector<uint8_t>& blob,
                                   uint8_t expected_owner,
                                   std::vector<uint8_t>* raw) {
  const Parsed parsed = Parse(blob);
  if (parsed.state == State::kNone) {
    *raw = blob;
    return UnwrapResult::kRaw;
  }
  if (parsed.state == State::kMalformed) return UnwrapResult::kMalformed;
  if (parsed.owner != expected_owner) return UnwrapResult::kOwnerMismatch;

  *raw = parsed.raw;
  return UnwrapResult::kUnwrapped;
}

}  // namespace teesim::hwblob
