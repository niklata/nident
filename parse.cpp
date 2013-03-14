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
#include <boost/regex.hpp>
#include <stdint.h>
#include <pwd.h>

extern "C" {
#include "blake256.h"
#include "log.h"
}

namespace ba = boost::asio;

extern bool gParanoid;

// XXX: extend config format to mask by local address?
bool Parse::parse_cfg(const std::string &fn, ba::ip::address sa, int sp,
                      ba::ip::address ca, int cp)
{
    std::string l;
    std::ifstream f(fn, std::ifstream::in);
    boost::regex re, rehost;
    boost::regex re_accept, re_deny, re_spoof, re_hash;
    boost::cmatch m;

    if (f.fail() || f.bad() || f.eof()) {
        std::cerr << "failed to open file: '" << fn << "'";
        goto out;
    }

    // x.x.x.x[/n] (*|l[:h]) (*|l[:h]) -> POLICY
    // x:x:x:x:x:x:x:x[/n] (*|l[:h]) (*|l[:h]) -> POLICY
    // x:x...x[::][/n] (*|l[:h]) (*|l[:h]) -> POLICY
    // POLICY:
    // deny||accept
    // spoof string
    // hash [uid] [ip] [sp] [cp]
    re.assign("\\s*([a-zA-Z0-9:.-]+)"//"\\s*([0-9A-Fa-f:.]+)" // ipv[46]
              "(?:/(\\d{1,2}))?"
              "\\s+(?:\\*|(\\d{1,5})(?::(\\d{1,5}))?)"
              "\\s+(?:\\*|(\\d{1,5})(?::(\\d{1,5}))?)"
              "\\s*->\\s*([a-zA-Z0-9 \\t]+)");
    // re4.assign("^((?:25[0-5]|(2[0-4]|1[0-9]|[1-9])?[0-9])\\.(?:25[0-5]|(2[0-4]|1[0-9]|[1-9])?[0-9])\\.(?:25[0-5]|(2[0-4]|1[0-9]|[1-9])?[0-9])\\.(?:25[0-5]|(2[0-4]|1[0-9]|[1-9])?[0-9]))");
    // re6.assign("^(((?=(?>.*?::)(?!.*::)))(::)?(([0-9A-F]{1,4})::?){0,5}|((?5):){6})(\\2((?5)(::?|$)){0,2}|((25[0-5]|(2[0-4]|1[0-9]|[1-9])?[0-9])(\\.|$)){4}|(?5):(?5))(?<![^:]:|\\.)\\z",
    //            boost::regex_constants::icase);
    rehost.assign("(?:\\.?[A-Za-z0-9-]{1,63})+");
    re_deny.assign("^deny\\s*", boost::regex_constants::icase);
    re_accept.assign("^accept\\s*", boost::regex_constants::icase);
    re_spoof.assign("^spoof\\s+([A-Za-z0-9]+)\\s*",
                    boost::regex_constants::icase);
    re_hash.assign("^hash(\\s+(?:uid|ip|sp|cp))+\\s*",
                   boost::regex_constants::icase);

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

        if (boost::regex_match(l.c_str(), m, re)) {
            const std::string hoststr = m[1];
            const std::string polstr = m[7];
            boost::cmatch n, o;
            ConfigItem ci;
            std::stringstream mask, llport, hlport, lrport, hrport;

            try {
                ci.host = ba::ip::address::from_string(hoststr);
            } catch (const boost::system::error_code &ec) {
                std::cerr << "bad host string: '" << hoststr << "'\n";
                continue; // invalid
            }

            if (!m[2].matched) {
                mask << std::dec << m[2];
                mask >> ci.mask;
                if (ci.host.is_v4() && ci.mask > 32)
                    ci.mask = 32;
                if (ci.mask > 128)
                    ci.mask = 128;
            }
            llport << std::dec << m[3];
            llport >> ci.low_lport;
            if (!m[4].matched) {
                hlport << std::dec << m[4];
                hlport >> ci.high_lport;
            }
            lrport << std::dec << m[5];
            lrport >> ci.low_rport;
            if (!m[6].matched) {
                hrport << std::dec << m[6];
                hrport >> ci.high_rport;
            }
            if (boost::regex_match(polstr.c_str(), o, re_deny)) {
                ci.policy.action = PolicyDeny;
            } else if (boost::regex_match(polstr.c_str(), o, re_accept)) {
                ci.policy.action = PolicyAccept;
            } else if (boost::regex_match(polstr.c_str(), o, re_spoof)) {
                ci.policy.action = PolicySpoof;
                ci.policy.spoof = o[1];
            } else if (boost::regex_match(polstr.c_str(), o, re_hash)) {
                ci.policy.action = PolicyHash;
                if (boost::regex_match(polstr.c_str(), o, boost::regex(".*?uid.*?")))
                    ci.policy.setHashUID();
                if (boost::regex_match(polstr.c_str(), o, boost::regex(".*?ip.*?")))
                    ci.policy.setHashIP();
                if (boost::regex_match(polstr.c_str(), o, boost::regex(".*?sp.*?")))
                    ci.policy.setHashSP();
                if (boost::regex_match(polstr.c_str(), o, boost::regex(".*?cp.*?")))
                    ci.policy.setHashCP();
            } else
                continue; // invalid
            if (ci.low_lport != -1 && sp < ci.low_lport)
                continue;
            if (ci.high_lport != -1 && sp > ci.high_lport)
                continue;
            if (ci.low_rport != -1 && cp < ci.low_rport)
                continue;
            if (ci.high_rport != -1 && cp > ci.high_rport)
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
    if (mask.is_v4())
        msize += 96;
    return compare_ipv6(ip.to_v6().to_bytes(), mask.to_v6().to_bytes(), msize);
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
    if (a == ma && b == mb)
        return true;
    else
        return false;
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
