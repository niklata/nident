/* parse.cpp - proc/net/tcp6? and config file parsing
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

#include "parse.hpp"
#include "siphash.hpp"

#include <string.h>
#include <nk/format.hpp>
#include <stdint.h>
#include <pwd.h>

namespace ba = boost::asio;

extern bool gParanoid;
extern uint64_t gSaltK0, gSaltK1;

std::string Parse::get_response(ba::ip::address sa, int sp,
                                ba::ip::address ca, int cp, int uid)
{
    if (!found_ci_ || ci_.policy.action == PolicyDeny) {
        if (gParanoid)
            return "ERROR:UNKNOWN-ERROR";
        else
            return "ERROR:HIDDEN-USER";
    } else if (ci_.policy.action == PolicyAccept) {
        return fmt::format("USERID:UNIX:{}", uid);
    } else if (ci_.policy.action == PolicySpoof) {
        if (!getpwnam(ci_.policy.spoof.c_str())) {
            return fmt::format("USERID:UNIX:{}", ci_.policy.spoof);
        } else {
            // A username exists with the spoof name.
            fmt::print(stderr, "Spoof requested for extant user {}\n",
                       ci_.policy.spoof);
            if (gParanoid)
                return "ERROR:UNKNOWN-ERROR";
            else
                return "ERROR:HIDDEN-USER";
        }
    } else if (ci_.policy.action == PolicyHash) {
        std::string hs;
        hs.reserve(32);
        if (ci_.policy.isHashUID())
            hs += fmt::format("{}", uid);
        if (ci_.policy.isHashIP())
            hs += ca.to_string();
        if (ci_.policy.isHashSP())
            hs += fmt::format("{}", sp);
        if (ci_.policy.isHashCP())
            hs += fmt::format("{}", cp);
        return fmt::format("USERID:UNIX:{}", compress_64_to_unix
                           (nk::siphash24_hash(gSaltK0, gSaltK1,
                                               hs.c_str(), hs.size())));
    }
    return "ERROR:UNKNOWN-ERROR";
}

static char cmap[] = {
    '0','1','2','3','4','5','6','7','8','9',
    'a','b','c','d','e','f','g','h','i','j',
    'k','l','m','n','o','p','q','r','s','t',
    'u','v','w','x','y','z','A','B','C','D',
    'E','F','G','H','I','J','K','L','M','N',
    'O','P','Q','R','S','T','U','V','W','X',
    'Y','Z','_','.'
};

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
    union {
        unsigned char c[8];
        uint64_t i;
    } b;
    char buf[9];
    buf[8] = '\0';
    b.i = qword;
    for (int i = 0; i < 8; ++i)
        buf[i] = cmap[b.c[i] & 0x3f];
    return std::string(buf);
}

