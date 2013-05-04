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
#include <iostream>
#include <fstream>
#include <sstream>
#include <boost/xpressive/xpressive_static.hpp>
#include <boost/algorithm/string.hpp>
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

// XXX: extend config format to mask by local address?
bool Parse::parse_cfg(const std::string &fn, ba::ip::address sa, int sp,
                      ba::ip::address ca, int cp)
{
    std::string l;
    std::ifstream f(fn, std::ifstream::in);

    // x.x.x.x[/n] (*|l[:h]) (*|l[:h]) -> POLICY
    // x:x:x:x:x:x:x:x[/n] (*|l[:h]) (*|l[:h]) -> POLICY
    // x:x...x[::][/n] (*|l[:h]) (*|l[:h]) -> POLICY
    // POLICY:
    // deny||accept
    // spoof string
    // hash [uid] [ip] [sp] [cp]

    using namespace boost::xpressive;
    mark_tag m_ip(1), m_mask(2), m_lolp(3), m_hilp(4), m_lorp(5), m_hirp(6),
             m_pol(7);
    mark_tag m_spoof(1);
    mark_tag m_hash(1);
    cregex re = (*blank >> (m_ip = +set[alnum|':'|'.'|'-'])
                 >> !('/' >> (m_mask = repeat<1,2>(_d)))
                 >> +blank >> ('*'|((m_lolp = repeat<1,5>(_d))
                                    >> !(':' >> (m_hilp = repeat<1,5>(_d)))))
                 >> +blank >> ('*'|((m_lorp = repeat<1,5>(_d))
                                    >> !(':' >> (m_hirp = repeat<1,5>(_d)))))
                 >> *blank >> "->" >> *blank >> (m_pol = +set[alnum|blank])
                 );
    cregex re_deny = (bos >> icase("deny") >> *blank);
    cregex re_accept = (bos >> icase("accept") >> *blank);
    cregex re_spoof = (bos >> icase("spoof") >> +blank
                       >> (m_spoof = +alnum) >> *blank);
    cregex re_hash = (bos >> icase("hash") >> (m_hash = +(+blank >> +alnum))
                      >> *blank);
    cmatch what;

    if (f.fail() || f.bad() || f.eof()) {
        std::cerr << "failed to open file: '" << fn << "'";
        goto out;
    }

    while (1) {
        std::getline(f, l);
        if (f.eof()) {
            break;
        } else if (f.bad()) {
            std::cerr << "fatal io error fetching line of " << fn << "\n";
            break;
        } else if (f.fail()) {
            std::cerr << "non-fatal io error fetching line of " << fn << "\n";
            break;
        }

        if (regex_search(l.c_str(), what, re)) {
            const std::string hoststr = what[m_ip];
            const std::string polstr = boost::to_lower_copy(what[m_pol].str());
            ConfigItem ci;
            std::stringstream mask, llport, hlport, lrport, hrport;

            try {
                ci.host = ba::ip::address::from_string(hoststr);
            } catch (const boost::system::error_code &ec) {
                std::cerr << "bad host string: '" << hoststr << "'\n";
                continue; // invalid
            }

            if (what[m_mask]) {
                mask << std::dec << what[m_mask].str();
                mask >> ci.mask;
                if (ci.host.is_v4() && ci.mask > 32)
                    ci.mask = 32;
                if (ci.mask > 128)
                    ci.mask = 128;
            }
            llport << std::dec << what[m_lolp].str();
            llport >> ci.low_lport;
            if (what[m_hilp]) {
                hlport << std::dec << what[m_hilp].str();
                hlport >> ci.high_lport;
            }
            lrport << std::dec << what[m_lorp].str();
            lrport >> ci.low_rport;
            if (what[m_hirp]) {
                hrport << std::dec << what[m_hirp].str();
                hrport >> ci.high_rport;
            }

            if (regex_match(polstr.c_str(), what, re_deny)) {
                ci.policy.action = PolicyDeny;
            } else if (regex_match(polstr.c_str(), what, re_accept)) {
                ci.policy.action = PolicyAccept;
            } else if (regex_match(polstr.c_str(), what, re_spoof)) {
                ci.policy.action = PolicySpoof;
                ci.policy.spoof = what[m_spoof];
            } else if (regex_match(polstr.c_str(), what, re_hash)) {
                ci.policy.action = PolicyHash;
                sregex reh = +blank;
                sregex_token_iterator
                    begin(polstr.begin(), polstr.end(), reh, -1), end;
                for (auto i = begin; i != end; ++i) {
                    if (*i == "uid")
                        ci.policy.setHashUID();
                    if (*i == "ip")
                        ci.policy.setHashIP();
                    if (*i == "sp")
                        ci.policy.setHashSP();
                    if (*i == "cp")
                        ci.policy.setHashCP();
                }
            } else
                continue; // invalid
            if (!port_in_bounds(sp, ci.low_lport, ci.high_lport))
                continue;
            if (!port_in_bounds(cp, ci.low_rport, ci.high_rport))
                continue;
            if (!compare_ip(ca, ci.host, ci.mask == -1 ? 0 : ci.mask))
                continue;
            found_ci_ = true;
            ci_ = ci;
            break;
        }
    }
    f.close();
  out:
    return found_ci_;
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

// Please note that compressing the 64-bit value will greatly lessen its
// entropy: the method I use will result in something with fewer than 48-bits
// of entropy, with the 'slightly' owing to numbers 0-6 being 25% more likely
// to occur than other alphanumerics and the alphanumeric mapping encoding
// slightly less than 6 bits of each byte.  However, as ident's responses
// should never be trusted, the security provided should be more than
// sufficient.  This approach saves more entropy than merely converting 32-bits
// of the qword to hex.
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
        b.c[i] = b.c[i] % 62;
        b.c[i] += 48;
        if (b.c[i] > 57) {
            b.c[i] += 7;
            if (b.c[i] > 90)
                b.c[i] += 6;
        }
        buf[i] = static_cast<char>(b.c[i]);
    }
    ss << buf;
    ss >> ret;
    return ret;
}
