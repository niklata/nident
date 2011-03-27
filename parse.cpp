/* parse.cpp - proc/net/tcp6? and config file parsing
 * Time-stamp: <2011-03-27 13:17:31 nk>
 *
 * (c) 2010-2011 Nicholas J. Kain <njkain at gmail dot com>
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

// Returns -1 if no match found, else the uid of the owner of the connection.
int Parse::parse_tcp(const std::string &fn, ba::ip::address_v4 sa, int sp,
                     ba::ip::address_v4 ca, int cp)
{
    std::string l;
    std::ifstream f(fn, std::ifstream::in);
    boost::regex re;
    boost::cmatch m;

    if (f.fail() || f.bad() || f.eof()) {
        std::cerr << "failed to open file: '" << fn << "'";
        goto out1;
    }

    // skip the header
    std::getline(f, l);
    if (f.eof()) {
        std::cerr << "no tcp connections\n";
        goto out;
    } else if (f.bad()) {
        std::cerr << "fatal io error getting first line of proc/net/tcp\n";
        goto out;
    } else if (f.fail()) {
        std::cerr << "non-fatal io error getting first line of proc/net/tcp\n";
        goto out;
    }

    // sl local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid
    // 0: 00000000:2383 00000000:0000 0A 00000000:00000000 00:00000000 00000000   109
    re.assign("\\s*\\d+:" // sl
              "\\s+([0-9a-fA-F]{2})([0-9a-fA-F]{2})([0-9a-fA-F]{2})([0-9a-fA-F]{2}):([0-9a-fA-F]{2})([0-9a-fA-F]{2})" // local
              "\\s+([0-9a-fA-F]{2})([0-9a-fA-F]{2})([0-9a-fA-F]{2})([0-9a-fA-F]{2}):([0-9a-fA-F]{2})([0-9a-fA-F]{2})" // remote
              "\\s+[0-9a-fA-F]{2}" // st
              "\\s+[0-9a-fA-F]{8}:[0-9a-fA-F]{8}" // tx_queue:rx_queue
              "\\s+[0-9a-fA-F]{2}:[0-9a-fA-F]{8}" // tr:tm->when
              "\\s+[0-9a-fA-F]{8}" // retrnsmt
              "\\s+(\\d+)" // uid
              "\\s+\\d+.*"); // timeout

    while (1) {
        std::getline(f, l);
        if (f.eof()) {
            break;
        } else if (f.bad()) {
            std::cerr << "fatal io error fetching line of proc/net/tcp\n";
            break;
        } else if (f.fail()) {
            std::cerr << "non-fatal io error fetching line of proc/net/tcp\n";
            break;
        }

        if (boost::regex_match(l.c_str(), m, re)) {
            ProcTcpItem ti;
            std::stringstream as, bs, cs, ds, es, fs, gs, hs, ls, rs, us;
            std::stringstream la4, ra4;
            unsigned int a, b, c, d, e, f, g, h;

            as << std::hex << m[4];
            as >> a;
            bs << std::hex << m[3];
            bs >> b;
            cs << std::hex << m[2];
            cs >> c;
            ds << std::hex << m[1];
            ds >> d;

            la4 << a << "." << b << "." << c << "." << d;
            ti.local_address_ = ba::ip::address::from_string(la4.str());
            ls << std::hex << m[5] << m[6];
            ls >> ti.local_port_;
            es << std::hex << m[10];
            es >> e;
            fs << std::hex << m[9];
            fs >> f;
            gs << std::hex << m[8];
            gs >> g;
            hs << std::hex << m[7];
            hs >> h;
            ra4 << e << "." << f << "." << g << "." << h;
            ti.remote_address_ = ba::ip::address::from_string(ra4.str());
            rs << std::hex << m[11] << m[12];
            rs >> ti.remote_port_;
            us << m[13];
            us >> ti.uid;
            if (ti.remote_port_ == cp && ti.local_port_ == sp) {
                if (ti.remote_address_.to_v4() != ca)
                    continue;
                if (ti.local_address_.to_v4() != sa)
                    continue;
                found_ti_ = true;
                ti_ = ti;
                break;
            }
        }
    }
  out:
    f.close();
  out1:
    return ti_.uid;
}

// Returns -1 if no match found, else the uid of the owner of the connection.
int Parse::parse_tcp6(const std::string &fn, ba::ip::address_v6 sa, int sp,
                      ba::ip::address_v6 ca, int cp)
{
    std::string l;
    std::ifstream f(fn, std::ifstream::in);
    boost::regex re;
    boost::cmatch m;

    if (f.fail() || f.bad() || f.eof()) {
        std::cerr << "failed to open file: '" << fn << "'";
        goto out1;
    }

    // skip the header
    std::getline(f, l);
    if (f.eof()) {
        std::cerr << "no tcp connections\n";
        goto out;
    } else if (f.bad()) {
        std::cerr << "fatal io error getting first line of proc/net/tcp\n";
        goto out;
    } else if (f.fail()) {
        std::cerr << "non-fatal io error getting first line of proc/net/tcp\n";
        goto out;
    }

    // sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
    // 12: 700401200000B4E20000000001000000:D063 28F1072601054000EFBEADDECCCCFECA:1A29 01 00000000:00000000 02:00053FAD 00000000  1000        0 4039830 2 ffff
    re.assign("\\s*\\d+:\\s+" // sl
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              ":([0-9a-fA-F]{2})([0-9a-fA-F]{2})" // local
              "\\s+"
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              ":([0-9a-fA-F]{2})([0-9a-fA-F]{2})" // remote
              "\\s+[0-9a-fA-F]{2}" // st
              "\\s+[0-9a-fA-F]{8}:[0-9a-fA-F]{8}" // tx_queue:rx_queue
              "\\s+[0-9a-fA-F]{2}:[0-9a-fA-F]{8}" // tr:tm->when
              "\\s+[0-9a-fA-F]{8}" // retrnsmt
              "\\s+(\\d+)" // uid
              "\\s+\\d+.*"); // timeout

    while (1) {
        std::getline(f, l);
        if (f.eof()) {
            break;
        } else if (f.bad()) {
            std::cerr << "fatal io error fetching line of proc/net/tcp\n";
            break;
        } else if (f.fail()) {
            std::cerr << "non-fatal io error fetching line of proc/net/tcp\n";
            break;
        }

        if (boost::regex_match(l.c_str(), m, re)) {
            ProcTcpItem ti;
            std::stringstream la6, ra6, ls, rs, us;

            la6 << m[4] << m[3] << ":" << m[2] << m[1] << ":"
                << m[8] << m[7] << ":" << m[6] << m[5] << ":"
                << m[12] << m[11] << ":" << m[10] << m[9] << ":"
                << m[16] << m[15] << ":" << m[14] << m[13];
            ti.local_address_ = ba::ip::address::from_string(la6.str());
            ls << std::hex << m[17] << m[18];
            ls >> ti.local_port_;
            ra6 << m[22] << m[21] << ":" << m[20] << m[19] << ":"
                << m[26] << m[25] << ":" << m[24] << m[23] << ":"
                << m[30] << m[29] << ":" << m[28] << m[27] << ":"
                << m[34] << m[33] << ":" << m[32] << m[31];
            ti.remote_address_ = ba::ip::address::from_string(ra6.str());
            rs << std::hex << m[35] << m[36];
            rs >> ti.remote_port_;
            us << m[37];
            us >> ti.uid;
            if (ti.remote_port_ == cp && ti.local_port_ == sp) {
                if (ti.remote_address_.to_v6() != ca)
                    continue;
                if (ti.local_address_.to_v6() != sa)
                    continue;
                found_ti_ = true;
                ti_ = ti;
                break;
            }
        }
    }
  out:
    f.close();
  out1:
    return ti_.uid;
}

// XXX: extend config format to mask by local address?
bool Parse::parse_cfg(const std::string &fn, ba::ip::address sa, int sp,
                      ba::ip::address ca, int cp)
{
    std::string l;
    std::ifstream f(fn, std::ifstream::in);
    boost::regex re, re4, re6, rehost;
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
    re4.assign("^((?:25[0-5]|(2[0-4]|1[0-9]|[1-9])?[0-9])\\.(?:25[0-5]|(2[0-4]|1[0-9]|[1-9])?[0-9])\\.(?:25[0-5]|(2[0-4]|1[0-9]|[1-9])?[0-9])\\.(?:25[0-5]|(2[0-4]|1[0-9]|[1-9])?[0-9]))");
    re6.assign("^(((?=(?>.*?::)(?!.*::)))(::)?(([0-9A-F]{1,4})::?){0,5}|((?5):){6})(\\2((?5)(::?|$)){0,2}|((25[0-5]|(2[0-4]|1[0-9]|[1-9])?[0-9])(\\.|$)){4}|(?5):(?5))(?<![^:]:|\\.)\\z",
               boost::regex_constants::icase);
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

            if (boost::regex_match(hoststr.c_str(), n, re6)) {
                ci.type = HostIP6;
                ci.host = ba::ip::address::from_string(hoststr);
            } else if (boost::regex_match(hoststr.c_str(), n, re4)) {
                ci.type = HostIP4;
                ci.host = ba::ip::address::from_string(hoststr);
            } else if (boost::regex_match(hoststr.c_str(), n, rehost)) {
                ci.type = HostName;
                // XXX support hostnames in config file
                std::cerr << "support for hostnames NYI\n";
                continue;
            } else
                continue; // invalid
            mask << std::dec << m[2];
            mask >> ci.mask;
            llport << std::dec << m[3];
            llport >> ci.low_lport;
            hlport << std::dec << m[4];
            hlport >> ci.high_lport;
            lrport << std::dec << m[5];
            lrport >> ci.low_rport;
            hrport << std::dec << m[6];
            hrport >> ci.high_rport;
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
    if (ip.is_v4()) {
        if (mask.is_v4()) {
            auto ip6 = ba::ip::address_v6::v4_mapped(ip.to_v4());
            auto mask6 = ba::ip::address_v6::v4_mapped(mask.to_v4());
            return compare_ipv6(ip6.to_bytes(), mask6.to_bytes(), 96 + msize);
        } else {
            auto ip6 = ba::ip::address_v6::v4_mapped(ip.to_v4());
            return compare_ipv6(ip6.to_bytes(), mask.to_v6().to_bytes(), msize);
        }
    } else {
        if (mask.is_v6()) {
            return compare_ipv6(ip.to_v6().to_bytes(),
                                mask.to_v6().to_bytes(), msize);
        } else {
            if (ip.to_v6().is_v4_mapped()) {
                auto mask6 = ba::ip::address_v6::v4_mapped(mask.to_v4());
                return compare_ipv6(ip.to_v6().to_bytes(), mask6.to_bytes(),
                                    96 + msize);
            } else
                return false;
        }
    }
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
Parse::get_response(ba::ip::address sa, int sp, ba::ip::address ca, int cp)
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
        ss << ti_.uid;
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
            sh << ti_.uid;
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
