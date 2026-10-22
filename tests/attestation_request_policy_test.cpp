#include "attestation_request_policy.h"

#include <array>
#include <cassert>

namespace {
struct Case {
  bool cert;
  bool challenge;
  bool attest_key;
  bool keep;
};
constexpr std::array<Case, 8> kCases{{
    {false, false, false, true},
    {false, false, true, true},
    {false, true, false, true},
    {false, true, true, true},
    {true, false, false, true},
    {true, false, true, false},
    {true, true, false, false},
    {true, true, true, false},
}};
constexpr bool AllPass() {
  for (const auto& c : kCases) {
    if (teesim::policy::KeepHardwareResultWithoutRewrite(c.cert, c.challenge, c.attest_key) != c.keep)
      return false;
  }
  return true;
}
static_assert(AllPass(), "attestation policy regression");
}  // namespace

int main() {
  assert(AllPass());
  return 0;
}
