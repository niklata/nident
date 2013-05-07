/* parse.cpp - proc/net/tcp6? and config file parsing
 *
 * (c) 2010-2013 Nicholas J. Kain <njkain at gmail dot com>
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

#include "parse.hpp"

#include <string.h>
#include <fstream>
#include <sstream>
#include <stdint.h>
#include <pwd.h>

extern "C" {
#include "blake256.h"
#include "log.h"
}

namespace ba = boost::asio;

extern bool gParanoid;
extern std::string gParseHashSalt;

bool Parse::port_in_bounds(int port, int lo, int hi)
{
    if (hi < 0)
        hi = lo;
    if (lo >= 0) {
        if (port < lo || port > hi)
            return false;
    }
    return true;
}

bool Parse::compare_ip(ba::ip::address ip, ba::ip::address mask, int msize)
{
    ba::ip::address_v6 ip6(ip.is_v4() ? ba::ip::address_v6::v4_mapped(ip.to_v4())
                           : ip.to_v6()), mask6;
    if (mask.is_v4()) {
        mask6 = ba::ip::address_v6::v4_mapped(mask.to_v4());
        msize += 96;
    } else
        mask6 = mask.to_v6();
    msize = std::min(msize, 128);
    return compare_ipv6(ip6.to_bytes(), mask6.to_bytes(), msize);
}

bool Parse::compare_ipv6(ba::ip::address_v6::bytes_type ip,
                         ba::ip::address_v6::bytes_type mask, int msize)
{
    if (msize > 128 || msize < 0)
        return false;

    uint64_t *idx, *idxm;
    idx = reinterpret_cast<uint64_t *>(&ip);
    idxm = reinterpret_cast<uint64_t *>(&mask);

    // these are stored in network byte order, not host byte order
    uint64_t b = idx[1];
    uint64_t a = idx[0];
    uint64_t mb = idxm[1];
    uint64_t ma = idxm[0];

    int incl_qwords = msize / 64;
    int incl_bits = msize % 64;

    if (incl_qwords == 0 && incl_bits == 0) { // wildcard mask
        return true;
    } else if (ma == 0 && mb == 0) { // wildcard
        return true;
    } else if (incl_qwords == 0 && incl_bits) {
        for (int i = 63 - incl_bits; i >= 0; --i) {
            a |= 1 << i;
            ma |= 1 << i;
        }
        b = mb;
    } else if (incl_qwords == 1 && incl_bits) {
        for (int i = 63 - incl_bits; i >= 0; --i) {
            b |= 1 << i;
            mb |= 1 << i;
        }
    }
    return a == ma && b == mb;
}

std::string
Parse::get_response(ba::ip::address sa, int sp, ba::ip::address ca, int cp,
                    int uid)
{
    std::stringstream ss;
    std::string ret;

    if (!found_ci_ || ci_.policy.action == PolicyDeny) {
        if (gParanoid)
            ss << "ERROR:UNKNOWN-ERROR";
        else
            ss << "ERROR:HIDDEN-USER";
    } else if (ci_.policy.action == PolicyAccept) {
        ss << "USERID:UNIX:";
        ss << uid;
    } else if (ci_.policy.action == PolicySpoof) {
        if (!getpwnam(ci_.policy.spoof.c_str())) {
            ss << "USERID:UNIX:";
            ss << ci_.policy.spoof;
        } else {
            // A username exists with the spoof name.
            log_line("Spoof requested for extant user %s",
                     ci_.policy.spoof.c_str());
            if (gParanoid)
                ss << "ERROR:UNKNOWN-ERROR";
            else
                ss << "ERROR:HIDDEN-USER";
        }
    } else if (ci_.policy.action == PolicyHash) {
        std::stringstream sh;
        std::string hashstr;
        sh << gParseHashSalt;
        if (ci_.policy.isHashUID())
            sh << uid;
        if (ci_.policy.isHashIP())
            sh << ca;
        if (ci_.policy.isHashSP())
            sh << sp;
        if (ci_.policy.isHashCP())
            sh << cp;
        sh >> hashstr;
        union hash_result_t {
            uint64_t u64[4];
            uint8_t u8[32];
        } result;
        blake256_hash(result.u8,
                      reinterpret_cast<const uint8_t *>(hashstr.c_str()),
                      hashstr.size());
        result.u64[0] ^= result.u64[1];
        result.u64[0] ^= result.u64[2];
        result.u64[0] ^= result.u64[3];
        ss << "USERID:UNIX:" << compress_64_to_unix(result.u64[0]);
    }
    ss >> ret;
    return ret;
}

/*  Technically ident allows username replies that consist of any valid octet
 *  that is not one of [\0\r\n].  It is most important to pick an destination
 *  alphabet size that divides the source alphabet size evenly so that the
 *  occurence of each character in the destination alphabet is equally likely.
 *
 *  Thus, the best choice is to map onto 64 values.  I choose [A-Za-z0-9_.].
 *  '.' is the least conservative choice from that set with regards to
 *  compatibility with broken software, but I feel it is somewhat less likely
 *  to break than '-'.
 */
std::string Parse::compress_64_to_unix(uint64_t qword)
{
    std::stringstream ss;
    std::string ret;
    union {
        unsigned char c[8];
        uint64_t i;
    } b;
    char buf[9];
    buf[8] = '\0';
    b.i = qword;
    for (int i = 0; i < 8; ++i) {
        b.c[i] = b.c[i] % 64;
        b.c[i] += 46; // incl '.'
        if (b.c[i] > 46) {
            b.c[i] += 1; // skip '/'
            if (b.c[i] > 57) {
                b.c[i] += 7;
                if (b.c[i] > 90) {
                    b.c[i] += 4; // incl '_'
                    if (b.c[i] > 95)
                        b.c[i] += 1; // skip '`'
                }
            }
        }
        buf[i] = static_cast<char>(b.c[i]);
    }
    ss << buf;
    ss >> ret;
    return ret;
}
