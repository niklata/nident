/* parsecfg.rl - proc/net/tcp6? and config file parsing
 *
 * (c) 2010-2014 Nicholas J. Kain <njkain at gmail dot com>
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

#include <cstdio>
#include <string.h>
#include <stdint.h>
#include <pwd.h>
#include <nk/format.hpp>
#include <nk/scopeguard.hpp>
#include "asio_addrcmp.hpp"
#include "parse.hpp"

#define MAX_LINE 2048

namespace ba = boost::asio;

// x.x.x.x[/n] (*|l[:h]) (*|l[:h]) -> POLICY
// x:x:x:x:x:x:x:x[/n] (*|l[:h]) (*|l[:h]) -> POLICY
// x:x...x[::][/n] (*|l[:h]) (*|l[:h]) -> POLICY
// POLICY:
// deny||accept
// spoof string
// hash [uid] [ip] [sp] [cp]

%%{
    machine cfg_parser;

    action SetPolDeny { ci.policy.action = PolicyDeny; }
    action SetPolAccept { ci.policy.action = PolicyAccept; }
    action SpoofSt { ci.policy.action = PolicySpoof; spoofstart = p; }
    action SpoofEn {
        ci.policy.spoof = std::string(spoofstart, p - spoofstart);
    }
    action SetPolHash { ci.policy.action = PolicyHash; }
    action SetHashUID { ci.policy.setHashUID(); }
    action SetHashIP  { ci.policy.setHashIP(); }
    action SetHashSP  { ci.policy.setHashSP(); }
    action SetHashCP  { ci.policy.setHashCP(); }
    action HostSt { hoststart = p; }
    action HostEn {
        hoststr = std::string(hoststart, p - hoststart);
        ci.host = ba::ip::address::from_string(hoststr);
    }
    action MaskSt { maskstart = p; }
    action MaskEn {
        char maskbuf[8] = {0};
        memcpy(maskbuf, maskstart, p - maskstart);
        ci.mask = atoi(maskbuf);
        if (ci.host.is_v4() && ci.mask > 32)
            ci.mask = 32;
        if (ci.mask > 128)
            ci.mask = 128;
    }
    action PortLoSt { portlo_start = p; }
    action PortLoEn {
        char pbuf[8] = {0};
        memcpy(pbuf, portlo_start, p - portlo_start);
        lport = atoi(pbuf);
    }
    action PortHiSt { porthi_start = p; }
    action PortHiEn {
        char pbuf[8] = {0};
        memcpy(pbuf, porthi_start, p - porthi_start);
        hport = atoi(pbuf);
    }
    action LocPortSt { lport = -1; hport = -1; }
    action LocPortEn { ci.low_lport = lport; ci.high_lport = hport; }
    action RemPortSt { lport = -1; hport = -1; }
    action RemPortEn { ci.low_rport = lport; ci.high_rport = hport; }

    ws       = [ \t];
    hashes   = ('uid'i % SetHashUID|'ip'i % SetHashIP|'sp'i % SetHashSP|'cp'i % SetHashCP);
    p_deny   = 'deny'i % SetPolDeny;
    p_accept = 'accept'i % SetPolAccept;
    p_spoof  = 'spoof'i ws+ ([^\n]+ > SpoofSt % SpoofEn);
    p_hash   = ('hash'i % SetPolHash) (ws+ hashes)+;

    ipv4   = digit{1,3} '.' digit{1,3} '.' digit{1,3} '.' digit{1,3};
    ipv6   = xdigit{0,4} (':'xdigit{0,4}){2,7}+;
    maskip = '/' digit{1,3};
    portr  = ('*'|(digit{1,5} > PortLoSt % PortLoEn)(':'(digit{1,5} > PortHiSt % PortHiEn))?);
    policy = (p_deny|p_accept|p_spoof|p_hash);

    main := ws* ((ipv4|ipv6) > HostSt % HostEn)
            (maskip? > MaskSt % MaskEn )
            ws+ (portr > LocPortSt % LocPortEn)
            ws+ (portr > RemPortSt % RemPortEn)
            ws* '->' ws* policy space*;
}%%

%% write data;

// XXX: extend config format to mask by local address?
bool Parse::parse_cfg(const std::string &fn, ba::ip::address sa, int sp,
                      ba::ip::address ca, int cp)
{
    char buf[MAX_LINE];
    auto f = fopen(fn.c_str(), "r");
    if (!f) {
        fmt::print(stderr, "{}: failed to open config file \"{}\": {}\n",
                   __func__, fn, strerror(errno));
        return found_ci_;
    }
    SCOPE_EXIT{ fclose(f); };
    while (!feof(f)) {
        auto fsv = fgets(buf, sizeof buf, f);
        auto llen = strlen(buf);
        if (buf[llen-1] == '\n')
            buf[--llen] = 0;
        if (!fsv) {
            if (!feof(f))
                fmt::print(stderr, "{}: io error fetching line of '{}'\n", __func__, fn);
            break;
        }
        if (llen == 0)
            continue;

        ConfigItem ci;
        std::string hoststr;
        const char *hoststart, *maskstart, *portlo_start, *porthi_start,
                   *spoofstart;
        int hport, lport;

        int cs = 0;
        const char *p = buf;
        const char *pe = p + llen;
        const char *eof = pe;

        try {
            %% write init;
            %% write exec;
        } catch (const boost::system::error_code &ec) {
            fmt::print(stderr, "{}: bad host string: '{}'\n", __func__, hoststr);
            continue; // invalid
        }

        if (cs < cfg_parser_first_final)
            continue;
        if (!nk::asio::port_in_bounds(sp, ci.low_lport, ci.high_lport))
            continue;
        if (!nk::asio::port_in_bounds(cp, ci.low_rport, ci.high_rport))
            continue;
        if (!nk::asio::compare_ip(ca, ci.host, ci.mask == -1 ? 0 : ci.mask))
            continue;
        found_ci_ = true;
        ci_ = ci;
        break;
    }
    return found_ci_;
}

