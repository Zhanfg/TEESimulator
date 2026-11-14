#include <cassert>
#include <cstdint>
#include <set>

#include "timing.h"

int main() {
  {
    TsDelayRange r{0, 0};
    assert(TsSampleDelayMs(r, 1) == 0);
    assert(TsSampleDelayMs(r, 999) == 0);
  }
  {
    TsDelayRange r{7, 7};
    assert(TsSampleDelayMs(r, 1) == 7);
    assert(TsSampleDelayMs(r, 1234567) == 7);
  }
  {
    TsDelayRange r{5, 17};
    std::set<uint32_t> seen;
    for (uint64_t seed = 1; seed <= 4096; ++seed) {
      const uint32_t v = TsSampleDelayMs(r, seed);
      assert(v >= 5 && v <= 17);
      seen.insert(v);
    }
    assert(seen.size() > 1);
  }
  {
    const TsDelayRange r = TsBoundedDelayRange(2500, 9000);
    assert(r.min_ms == 2000);
    assert(r.max_ms == 2000);
  }
  {
    const TsDelayRange r = TsBoundedDelayRange(1500, 1000);
    assert(r.min_ms == 1000);
    assert(r.max_ms == 1000);
  }
  return 0;
}
