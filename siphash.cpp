/* siphash.cpp - simple siphash implementation, optimal for 64-bit
 *
 * (c) 2012-2013 Nicholas J. Kain <njkain at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
namespace nk {

#ifdef __GNUC__
#define FORCE_INLINE inline __attribute__((always_inline))
#else
#define FORCE_INLINE inline
#endif

#include <stddef.h>
#include <stdint.h>
#include <boost/detail/endian.hpp>

static uint64_t FORCE_INLINE rotl(uint64_t x, uint64_t d)
{
    return (x << d) | (x >> (64 - d));
}

#ifdef BOOST_BIG_ENDIAN
static FORCE_INLINE uint64_t bswap(uint64_t x) {
    return x << 56 | ((x << 40) & 0xff000000000000) | ((x << 24) & 0xff0000000000)
        | ((x << 8) & 0xff00000000) | ((x >> 8) & 0xff000000)
        | ((x >> 24) & 0xff0000) | ((x >> 40) & 0xff00) | x >> 56;
}
#endif

#define SIPROUND() do { \
    v0 += v1; \
    v1 = nk::rotl(v1, 13); \
    v1 ^= v0; \
    v0 = nk::rotl(v0, 32); \
    v2 += v3; \
    v3 = nk::rotl(v3, 16); \
    v3 ^= v2; \
    v0 += v3; \
    v3 = nk::rotl(v3, 21); \
    v3 ^= v0; \
    v2 += v1; \
    v1 = nk::rotl(v1, 17); \
    v1 ^= v2; \
    v2 = nk::rotl(v2, 32); \
    } while(0)

uint64_t siphash24_hash(const uint64_t k0, const uint64_t k1,
                        const char * const str, const size_t size)
{
    uint64_t v0 = k0 ^ 0x736f6d6570736575ull;
    uint64_t v1 = k1 ^ 0x646f72616e646f6dull;
    uint64_t v2 = k0 ^ 0x6c7967656e657261ull;
    uint64_t v3 = k1 ^ 0x7465646279746573ull;
    uint64_t m;
    size_t w = size / 8;
    for (size_t i = 0; i < w; ++i) {
#ifdef BOOST_BIG_ENDIAN
        m = nk::bswap(reinterpret_cast<const uint64_t *>(str)[i]);
#else
        m = reinterpret_cast<const uint64_t *>(str)[i];
#endif
        v3 ^= m;
        for (size_t k = 0; k < 2; ++k)
            SIPROUND();
        v0 ^= m;
    }
    m = (size & 0xff) << 56;
    const auto s8 = str + w * 8;
    switch (size & 0x07) {
    case 7: m |= static_cast<uint64_t>(s8[6]) << 48;
    case 6: m |= static_cast<uint64_t>(s8[5]) << 40;
    case 5: m |= static_cast<uint64_t>(s8[4]) << 32;
    case 4: m |= static_cast<uint64_t>(s8[3]) << 24;
    case 3: m |= static_cast<uint64_t>(s8[2]) << 16;
    case 2: m |= static_cast<uint64_t>(s8[1]) << 8;
    case 1: m |= static_cast<uint64_t>(s8[0]);
    case 0: default:;
    }
    v3 ^= m;
    for (size_t k = 0; k < 2; ++k)
        SIPROUND();
    v0 ^= m;

    v2 ^= 0xff;
    for (size_t k = 0; k < 4; ++k)
        SIPROUND();
    return v0 ^ v1 ^ v2 ^ v3;
}
}

