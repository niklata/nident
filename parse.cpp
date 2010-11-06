/* parse.cpp - proc/net/tcp6? and config file parsing
 * Time-stamp: <2010-11-06 02:14:52 nk>
 *
 * (c) 2010 Nicholas J. Kain <njkain at gmail dot com>
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

extern bool gParanoid;

void Parse::parse_tcp(const std::string &fn)
{
    std::string l;
    std::ifstream f(fn, std::ifstream::in);
    boost::regex re;
    boost::cmatch m;

    if (f.fail() || f.bad() || f.eof()) {
        std::cerr << "failed to open file: '" << fn << "'";
        return;
    }

    // skip the header
    std::getline(f, l);
    if (f.eof()) {
        std::cerr << "no tcp connections\n";
        f.close();
        return;
    } else if (f.bad()) {
        std::cerr << "fatal io error getting first line of proc/net/tcp\n";
        f.close();
        return;
    } else if (f.fail()) {
        std::cerr << "non-fatal io error getting first line of proc/net/tcp\n";
        f.close();
        return;
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
            std::cerr << "end of tcp connections\n";
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
            std::stringstream la6, ra6;
            unsigned int a, b, c, d, e, f, g, h;

            as << std::hex << m[4];
            as >> a;
            bs << std::hex << m[3];
            bs >> b;
            cs << std::hex << m[2];
            cs >> c;
            ds << std::hex << m[1];
            ds >> d;
            la6 << "0000:0000:0000:0000:0000:ffff:"
                << a << "." << b << "." << c << "." << d;
            ti.local_address_ = canon_ipv6(la6.str());
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
            ra6 << "0000:0000:0000:0000:0000:ffff:"
                << e << "." << f << "." << g << "." << h;
            ti.remote_address_ = canon_ipv6(ra6.str());
            rs << std::hex << m[11] << m[12];
            rs >> ti.remote_port_;
            us << m[13];
            us >> ti.uid;
            tcp_items.push_back(ti);

            std::cout << "local: " << "0000:0000:0000:0000:0000:ffff:"
                      << a << "." << b << "." << c << "." << d << "\n";
            std::cout << "lport: " << ti.local_port_ << "\n";
            std::cout << "rmote: " << "0000:0000:0000:0000:0000:ffff:"
                      << e << "." << f << "." << g << "." << h << "\n";
            std::cout << "rport: " << ti.remote_port_ << "\n";
            std::cout << "uid: " << m[13] << "\n";
        }
    }
    f.close();
}

void Parse::parse_tcp6(const std::string &fn)
{
    std::string l;
    std::ifstream f(fn, std::ifstream::in);
    boost::regex re;
    boost::cmatch m;

    if (f.fail() || f.bad() || f.eof()) {
        std::cerr << "failed to open file: '" << fn << "'";
        return;
    }

    // skip the header
    std::getline(f, l);
    if (f.eof()) {
        std::cerr << "no tcp connections\n";
        f.close();
        return;
    } else if (f.bad()) {
        std::cerr << "fatal io error getting first line of proc/net/tcp\n";
        f.close();
        return;
    } else if (f.fail()) {
        std::cerr << "non-fatal io error getting first line of proc/net/tcp\n";
        f.close();
        return;
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
            std::cerr << "end of tcp connections\n";
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
            ti.local_address_ = canon_ipv6(la6.str());
            ls << std::hex << m[17] << m[18];
            ls >> ti.local_port_;
            ra6 << m[22] << m[21] << ":" << m[20] << m[19] << ":"
                << m[26] << m[25] << ":" << m[24] << m[23] << ":"
                << m[30] << m[29] << ":" << m[28] << m[27] << ":"
                << m[34] << m[33] << ":" << m[32] << m[31];
            ti.remote_address_ = canon_ipv6(ra6.str());
            rs << std::hex << m[35] << m[36];
            rs >> ti.remote_port_;
            us << m[37];
            us >> ti.uid;
            tcp_items.push_back(ti);

            std::cout << "local: " << la6.str() << "\n";
            std::cout << "lport: " << ti.local_port_ << "\n";
            std::cout << "rmote: " << ra6.str() << "\n";
            std::cout << "rport: " << ti.remote_port_ << "\n";
            std::cout << "uid: " << ti.uid << "\n";
        }
    }
    f.close();
}

void Parse::parse_cfg(const std::string &fn)
{
    std::string l;
    std::ifstream f(fn, std::ifstream::in);
    boost::regex re, re4, re6, rehost;
    boost::regex re_accept, re_deny, re_spoof, re_hash;
    boost::cmatch m;

    if (f.fail() || f.bad() || f.eof()) {
        std::cerr << "failed to open file: '" << fn << "'";
        return;
    }

    // x.x.x.x[/n] (*|l[:h]) (*|l[:h]) -> POLICY
    // x:x:x:x:x:x:x:x[/n] (*|l[:h]) (*|l[:h]) -> POLICY
    // x:x...x[::][/n] (*|l[:h]) (*|l[:h]) -> POLICY
    // POLICY:
    // deny||accept
    // spoof string
    // hash [uid] [ip] [sp] [dp]
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
    re_hash.assign("^hash(\\s+(?:uid|ip|sp|dp))+\\s*",
                   boost::regex_constants::icase);

    while (1) {
        std::getline(f, l);
        std::cout << "\n" << l << "\n";
        if (f.eof()) {
            std::cerr << "end of tcp connections\n";
            break;
        } else if (f.bad()) {
            std::cerr << "fatal io error fetching line of proc/net/tcp\n";
            break;
        } else if (f.fail()) {
            std::cerr << "non-fatal io error fetching line of proc/net/tcp\n";
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
                ci.host = canon_ipv6(hoststr);
            } else if (boost::regex_match(hoststr.c_str(), n, re4)) {
                std::string tmpstr;
                ci.type = HostIP4;
                tmpstr += "::ffff:";
                tmpstr += hoststr;
                ci.host = canon_ipv6(tmpstr);
            } else if (boost::regex_match(hoststr.c_str(), n, rehost)) {
                ci.type = HostName;
                // XXX support hostnames in config file
                std::cerr << "support for hostnames NYI\n";
                ci.host = canon_ipv6("::1");
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
                if (boost::regex_match(polstr.c_str(), o, boost::regex(".*?dp.*?")))
                    ci.policy.setHashDP();
            } else
                continue; // invalid
            cfg_items.push_back(ci);

            if (ci.type == HostIP6)
                std::cout << "ipv6: " << hoststr << "\n";
            else if (ci.type == HostIP4)
                std::cout << "ipv4: " << hoststr << "\n";
            else if (ci.type == HostName)
                std::cout << "host: " << hoststr << "\n";
            else
                continue; // invalid
            std::cout << "mask size: " << ci.mask << "\n";
            std::cout << "local low port: " << ci.low_lport << "\n";
            std::cout << "local high port: " << ci.high_lport << "\n";
            std::cout << "remote low port: " << ci.low_rport << "\n";
            std::cout << "remote high port: " << ci.high_rport << "\n";
            if (ci.policy.action == PolicyDeny)
                std::cout << "Policy: deny\n";
            else if (ci.policy.action == PolicyAccept)
                std::cout << "Policy: accept\n";
            else if (ci.policy.action == PolicySpoof)
                std::cout << "Policy: spoof [" << ci.policy.spoof << "]\n";
            else if (ci.policy.action == PolicyHash) {
                std::cout << "Policy: hash";
                if (ci.policy.isHashUID())
                    std::cout << " uid";
                if (ci.policy.isHashIP())
                    std::cout << " ip";
                if (ci.policy.isHashSP())
                    std::cout << " sp";
                if (ci.policy.isHashDP())
                    std::cout << " dp";
                std::cout << "\n";
            } else
                continue; // invalid
        }
    }
    std::cout << "end of config\n";
    f.close();
}

// Forms a proper ipv6 address lacking '::' and '.'
struct in6_addr Parse::canon_ipv6(const std::string &ip, bool *ok)
{
    struct in6_addr ret;
    int r;

    r = inet_pton(AF_INET6, ip.c_str(), &ret);
    if (r == 0) {
        if (ok)
            *ok = false;
        std::cerr << "canon_ipv6: not in presentation format\n";
    } else if (r < 0) {
        if (ok)
            *ok = false;
        std::cerr << "canon_ipv6: inet_pton() error " << strerror(errno) << "\n";
    }
    if (ok)
        *ok = true;
    unsigned int *idx;
    idx = reinterpret_cast<unsigned int *>(&ret);
    std::cout << "ip raw :" << idx[3] << " " << idx[2] << " " << idx[1] << " " << idx[0] << "\n";
    return ret;
}

bool Parse::compare_ipv6(struct in6_addr ip, struct in6_addr mask,
                         int msize)
{
    unsigned int *idx, *idxm;
    idx = reinterpret_cast<unsigned int *>(&ip);
    idxm = reinterpret_cast<unsigned int *>(&mask);
    // network is always big endian
    unsigned int d = idx[0];
    unsigned int c = idx[1];
    unsigned int b = idx[2];
    unsigned int a = idx[3];
    unsigned int md = idxm[0];
    unsigned int mc = idxm[1];
    unsigned int mb = idxm[2];
    unsigned int ma = idxm[3];

    char buf[32];
    inet_ntop(AF_INET6, &ip, buf, sizeof buf);
    std::cout << "cmp ip: " << buf << "\n";
    inet_ntop(AF_INET6, &mask, buf, sizeof buf);
    std::cout << "cmpmsk: " << buf << " bits: " << msize << "\n";
    std::cout << "\na: " << a << " b: " << b << " c: " << c << " d: " << d << "\n";
    std::cout << "ma: " << ma << " mb: " << mb << " mc: " << mc << " md: " << md << "\n";

    int incl_dwords = msize / 32;
    int incl_bits = msize % 32;
    std::cout << "incl_dwords = " << incl_dwords << " incl_bits = " << incl_bits << "\n";
    if (incl_dwords == 0 && incl_bits == 0) { // wildcard mask
        return true;
    } else if (ma == 0 && mb == 0 && mc == 0 && md == 0) { // wildcard
        return true;
    } else if (incl_dwords == 0 && incl_bits) {
        for (int i = 32 - incl_bits; i > 0; --i) {
            a |= 1 << i;
            ma |= 1 << i;
        }
        b = mb; c = mc; d = md;
    } else if (incl_dwords == 1 && incl_bits) {
        for (int i = 32 - incl_bits; i > 0; --i) {
            b |= 1 << i;
            mb |= 1 << i;
        }
        c = mc; d = md;
    } else if (incl_dwords == 2 && incl_bits) {
        for (int i = 32 - incl_bits; i > 0; --i) {
            c |= 1 << i;
            mc |= 1 << i;
        }
        d = md;
    } else if (incl_dwords == 3 && incl_bits) {
        for (int i = 32 - incl_bits; i > 0; --i) {
            d |= 1 << i;
            md |= 1 << i;
        }
    }
    if (a == ma && b == mb && c == mc && d == md)
        return true;
    else
        return false;
}

// XXX: extend config format to mask by local address?
std::string Parse::get_response(struct in6_addr sa, int sp,
                                struct in6_addr ca, int cp)
{
    std::stringstream ss;
    std::string ret;

    bool cmatched = false;
    int uid;
    std::vector<ConfigItem>::iterator c;
    for (c = cfg_items.begin(); c != cfg_items.end(); ++c) {
        std::cout << ".";
        if (c->low_lport != -1 && sp < c->low_lport)
            continue;
        if (c->high_lport != -1 && sp > c->high_lport)
            continue;
        if (c->low_rport != -1 && cp < c->low_rport)
            continue;
        if (c->high_rport != -1 && cp > c->high_rport)
            continue;
        std::cout << "*";
        if (!compare_ipv6(ca, c->host, c->mask == -1 ? 0 : c->mask))
            continue;
        // Found our match.
        std::cout << "cmatch = true\n";
        cmatched = true;
        break;
    }
    std::cout << "\n";
    if (cmatched) {
        std::vector<ProcTcpItem>::iterator t;
        for (t = tcp_items.begin(); t != tcp_items.end(); ++t) {
            std::cout << "rp: " << t->remote_port_ << " cp: " << cp << "\n";
            if (t->remote_port_ != cp)
                continue;
            std::cout << "1";
            if (t->local_port_ != sp)
                continue;
            std::cout << "2";
            if (memcmp(&t->remote_address_, &ca, sizeof (struct in6_addr)))
                continue;
            std::cout << "3";
            if (memcmp(&t->local_address_, &sa, sizeof (struct in6_addr)))
                continue;
            std::cout << "4";
            uid = t->uid;
            if (c->policy.action == PolicyNone) {
                std::cout << "action: PolicyNone\n";
                if (gParanoid)
                    ss << "ERROR:UNKNOWN-ERROR";
                else
                    ss << "ERROR:NO-USER";
            } else if (c->policy.action == PolicyAccept) {
                std::cout << "action: PolicyAccept\n";
                ss << "USERID:UNIX:";
                ss << uid;
            } else if (c->policy.action == PolicyDeny) {
                std::cout << "action: PolicyDeny\n";
                if (gParanoid)
                    ss << "ERROR:UNKNOWN-ERROR";
                else
                    ss << "ERROR:HIDDEN-USER";
            } else if (c->policy.action == PolicySpoof) {
                std::cout << "action: PolicySpoof\n";
                ss << "USERID:UNIX:";
                ss << c->policy.spoof;
            } else if (c->policy.action == PolicyHash) {
                std::cout << "action: PolicyHash\n";
                // XXX NYI, bool policy->is*()
                // fHashNone = 0,
                //     fHashUID = 1,
                //     fHashIP = 2,
                //     fHashSP = 4,
                //     fHashDP = 8
                ss << "USERID:UNIX:hash-NYI";
            }
            break;
        }
    } else {
        std::cout << "action: default (no hits)\n";
        if (gParanoid)
            ss << "ERROR:UNKNOWN-ERROR";
        else
            ss << "ERROR:NO-USER";
    }
    ss >> ret;
    return ret;
}
