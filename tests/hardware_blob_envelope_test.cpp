#include "hardware_blob_envelope.h"

#include <cassert>
#include <cstdint>
#include <vector>

using namespace teesim::hwblob;

int main() {
  const std::vector<uint8_t> raw = {0x01, 0x02, 0x03, 0xfe, 0xff};

  // Historical genuine hardware blobs are untouched.
  {
    std::vector<uint8_t> out;
    assert(UnwrapForOwner(raw, kTrustedEnvironment, &out) == UnwrapResult::kRaw);
    assert(out == raw);
    assert(Parse(raw).state == State::kNone);
  }

  // TEE owner survives round-trip and the HAL payload is byte-for-byte identical.
  const auto tee = Wrap(kTrustedEnvironment, raw);
  assert(tee.has_value());
  {
    const Parsed parsed = Parse(*tee);
    assert(parsed.state == State::kValid);
    assert(parsed.owner == kTrustedEnvironment);
    assert(parsed.raw == raw);

    std::vector<uint8_t> out;
    assert(UnwrapForOwner(*tee, kTrustedEnvironment, &out) == UnwrapResult::kUnwrapped);
    assert(out == raw);
  }

  // Wrapping twice for the same owner is idempotent; changing owner is not.
  {
    const auto again = Wrap(kTrustedEnvironment, *tee);
    assert(again.has_value());
    assert(*again == *tee);
    assert(!Wrap(kStrongBox, *tee).has_value());
  }

  // StrongBox is a distinct persistent owner; a TEE proxy must reject it.
  const auto sb = Wrap(kStrongBox, raw);
  assert(sb.has_value());
  {
    std::vector<uint8_t> out;
    assert(UnwrapForOwner(*sb, kStrongBox, &out) == UnwrapResult::kUnwrapped);
    assert(out == raw);
    assert(UnwrapForOwner(*sb, kTrustedEnvironment, &out) ==
           UnwrapResult::kOwnerMismatch);
  }

  // Truncation after the magic must not downgrade to the legacy-raw path.
  {
    std::vector<uint8_t> truncated(kMagic, kMagic + sizeof(kMagic));
    std::vector<uint8_t> out;
    assert(Parse(truncated).state == State::kMalformed);
    assert(UnwrapForOwner(truncated, kTrustedEnvironment, &out) ==
           UnwrapResult::kMalformed);
  }

  // Reserved bits, invalid version/owner and forged length all fail as malformed.
  {
    auto bad = *tee;
    bad[10] = 1;
    assert(Parse(bad).state == State::kMalformed);

    bad = *tee;
    bad[8] = 0xff;
    assert(Parse(bad).state == State::kMalformed);

    bad = *tee;
    bad[9] = 0;
    assert(Parse(bad).state == State::kMalformed);

    bad = *tee;
    bad[15] ^= 0x01;
    assert(Parse(bad).state == State::kMalformed);
  }

  // Empty blobs are never enveloped and an empty-length forged envelope is invalid.
  assert(!Wrap(kTrustedEnvironment, {}).has_value());
  {
    std::vector<uint8_t> empty(kHeaderSize, 0);
    std::memcpy(empty.data(), kMagic, sizeof(kMagic));
    empty[8] = kVersion;
    empty[9] = kTrustedEnvironment;
    assert(Parse(empty).state == State::kMalformed);
  }

  return 0;
}
