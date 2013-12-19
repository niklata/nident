/* parse.hpp - proc/net/tcp6? and config file parsing
 * Time-stamp: <2011-03-28 21:04:40 nk>
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

#ifndef PARSE_H_
#define PARSE_H_

#include <string>
#include <boost/asio.hpp>

class Parse {
public:
    enum PolicyAction {
        PolicyDeny,
        PolicyAccept,
        PolicySpoof,
        PolicyHash
    };
    struct Policy {
        enum HashItem {
            fHashNone = 0,
            fHashUID = 1,
            fHashIP = 2,
            fHashSP = 4,
            fHashCP = 8
        };
        PolicyAction action;
        std::string spoof;
        Policy() { action = PolicyDeny; hashitems = fHashNone; }
        void setHashUID() { hashitems |= fHashUID; }
        void setHashIP() { hashitems |= fHashIP; }
        void setHashSP() { hashitems |= fHashSP; }
        void setHashCP() { hashitems |= fHashCP; }
        bool isHashUID() const { return (hashitems & fHashUID) ? true : false; }
        bool isHashIP() const { return (hashitems & fHashIP) ? true : false; }
        bool isHashSP() const { return (hashitems & fHashSP) ? true : false; }
        bool isHashCP() const { return (hashitems & fHashCP) ? true : false; }
    private:
        int hashitems;
    };
    struct ConfigItem {
        boost::asio::ip::address host;
        int mask;
        int low_lport;
        int high_lport;
        int low_rport;
        int high_rport;
        Policy policy;
        ConfigItem()
            :  mask(-1), low_lport(-1), high_lport(-1),
              low_rport(-1), high_rport(-1) {}
    };
    Parse() {
        found_ci_ = false;
    }
    std::string get_response(boost::asio::ip::address sa, int sp,
                             boost::asio::ip::address ca, int cp, int uid);
    bool parse_cfg(const std::string &fn,
                   boost::asio::ip::address sa, int sp,
                   boost::asio::ip::address ca, int cp);
private:
    std::string compress_64_to_unix(uint64_t qword);
    bool found_ci_;
    ConfigItem ci_;
};

#endif /* PARSE_H_ */
