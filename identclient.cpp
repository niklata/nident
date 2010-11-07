/* identclient.cpp - ident client request handling
 * Time-stamp: <2010-11-06 20:53:56 nk>
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

#include <sstream>
#include <iostream>

#include <unistd.h>
#include <string.h> // memset

#include <sys/types.h>
#include <pwd.h>

#include "epoll.hpp"
#include "identclient.hpp"
#include "parse.hpp"

extern "C" {
#include "log.h"
}

extern bool gParanoid;
unsigned int max_client_bytes = 128;

IdentClient::IdentClient(int fd) : fd_(fd) {
    state_ = STATE_WAITIN;
    server_type_ = HostNone;
    client_type_ = HostNone;
    server_port_ = -1;
    client_port_ = -1;
}

IdentClient::~IdentClient() {
    close(fd_);
}

// Returns false if the object needs to be destroyed by the caller.
// State can change: STATE_WAITIN -> STATE_GOTIN
bool IdentClient::process_input()
{
    if (state_ != STATE_WAITIN) {
        return false;
    }
    char buf[max_client_bytes];
    memset(buf, 0, sizeof buf);
    ssize_t len = 0;
    while (len < max_client_bytes) {
        ssize_t r = read(fd_, buf + len, (sizeof buf) - len);
        if (r == 0)
            break;
        if (r == -1) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            log_line("fd %i: read() error %d", fd_, strerror(errno));
            return false;
        }
        len += r;
    }

    // Remote end hung up.
    if (len == 0)
        return false;

    for (int i = 0; i < len; ++i) {
        if (buf[i] == '\n' || buf[i] == '\r') {
            inbuf_ += buf[i];
            state_ = STATE_GOTIN;
            break;
        }
        if (inbuf_.size() + 1 > max_client_bytes) {
            log_line("fd %i: flood from peer (more than %i bytes), closing",
                     fd_, max_client_bytes);
            return false;
        }
        inbuf_ += buf[i];
    }
    if (state_ == STATE_GOTIN) {
        unschedule_read(fd_);
        if (!create_reply())
            return false;
    }
    return true;
}

// Returns ParseInvalid if the object needs to be destroyed by the caller.
IdentClient::ParseState IdentClient::parse_request()
{
    ParseState state = ParseServerPort;
    int prev_idx = 0;
    int sp_len = 0;
    int cp_len = 0;
    size_t i;
    bool found_num = false;
    bool found_ws_after_num = false;
    for (i = 0; i < inbuf_.size(); ++i) {
        const char c = inbuf_.at(i);
        if (state == ParseServerPort) {
            switch (c) {
                case ' ':
                case '\t':
                    if (found_num)
                        found_ws_after_num = true;
                    continue;
                case ',': {
                    std::string sport = inbuf_.substr(prev_idx, i);
                    std::stringstream ss;
                    ss << sport;
                    ss >> server_port_;
                    if (server_port_ < 1 || server_port_ > 65535) {
                        state = ParseBadPort;
                        return state;
                    }
                    state = ParseClientPort;
                    prev_idx = i + 1;
                    found_num = false;
                    found_ws_after_num = false;
                    continue;
                }
                case '0': case '1': case '2': case '3': case '4':
                case '5': case '6': case '7': case '8': case '9':
                    if (found_num == false) {
                        found_num = true;
                        prev_idx = i;
                    }
                    if (found_ws_after_num) {
                        state = ParseInvalid;
                        return state;
                    }
                    if (++sp_len > 5) {
                        state = ParseBadPort;
                        return state;
                    }
                    continue;
                default:
                    state = ParseInvalid;
                    return state;
            }
        } else if (state == ParseClientPort) {
            switch (c) {
                case ' ':
                case '\t':
                    if (found_num)
                        found_ws_after_num = true;
                    continue;
                case '\r':
                case '\n':
                    goto eol;
                case '0': case '1': case '2': case '3': case '4':
                case '5': case '6': case '7': case '8': case '9':
                    if (found_num == false) {
                        found_num = true;
                        prev_idx = i;
                    }
                    if (found_ws_after_num) {
                        state = ParseInvalid;
                        return state;
                    }
                    if (++cp_len > 5) {
                        state = ParseBadPort;
                        return state;
                    }
                    continue;
                default:
                    state = ParseInvalid;
                    return state;
            }
        }
    }
  eol:
    if (state == ParseClientPort && found_num) {
        std::string cport = inbuf_.substr(prev_idx, i);
        std::stringstream ss;
        ss << cport;
        ss >> client_port_;
        if (client_port_ < 1 || client_port_ > 65535) {
            state = ParseBadPort;
            return state;
        }
        state = ParseDone;
        return state;
    }
    return ParseInvalid;
}

bool IdentClient::decipher_addr(const struct sockaddr_storage &addr,
                                struct in6_addr *addy, HostType *htype,
                                std::string *addyp)
{
    if (addr.ss_family == AF_INET) {
        char hoststr[32];
        struct sockaddr_in *s = (struct sockaddr_in *)&addr;
        int r;
        if (htype)
            *htype = HostIP4;
        if (!inet_ntop(AF_INET, &s->sin_addr, hoststr, sizeof hoststr)) {
            log_line("inet_ntop (ipv4): %s", strerror(errno));
            return false;
        }
        if (addyp)
            *addyp = hoststr;
        std::string hoststr6;
        hoststr6 += "::ffff:";
        hoststr6 += hoststr;
        r = inet_pton(AF_INET6, hoststr6.c_str(), addy);
        if (r == 0) {
            log_line("inet_pton (ipv4): invalid address");
            return false;
        } else if (r < 0) {
            log_line("inet_pton (ipv4): %s", strerror(errno));
            return false;
        }
    } else if (addr.ss_family == AF_INET6) {
        char hoststr[32];
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
        int r;
        if (htype)
            *htype = HostIP6;
        if (!inet_ntop(AF_INET6, &s->sin6_addr, hoststr, sizeof hoststr)) {
            log_line("inet_ntop (ipv6): %s", strerror(errno));
            return false;
        }
        if (addyp)
            *addyp = hoststr;
        r = inet_pton(AF_INET6, hoststr, addy);
        if (r == 0) {
            log_line("inet_pton (ipv6): invalid address");
            return false;
        } else if (r < 0) {
            log_line("inet_pton (ipv6): %s", strerror(errno));
            return false;
        }
    } else {
        log_line("getsockname(): returned unknown ss_family");
        return false;
    }
    return true;
}

// Returns true if sock IP and port are found, else false.
bool IdentClient::get_local_info()
{
    struct sockaddr_storage addr;
    socklen_t len = sizeof addr;
    if (getsockname(fd_, (struct sockaddr *)&addr, &len)) {
        log_line("getsockname() error %s", strerror(errno));
        return false;
    }
    if (decipher_addr(addr, &server_address_, &server_type_))
        return true;
    else
        return false;
}

// Returns true if peer IP and port are found, else false.
bool IdentClient::get_peer_info()
{
    struct sockaddr_storage addr;
    socklen_t len = sizeof addr;
    if (getpeername(fd_, (struct sockaddr *)&addr, &len)) {
        log_line("getpeername() error %s", strerror(errno));
        return false;
    }
    if (decipher_addr(addr, &client_address_, &client_type_,
                      &client_address_pretty_))
        return true;
    else
        return false;
}

// Forms a reply and schedules a write.
// State can change: STATE_GOTIN -> STATE_WAITOUT
bool IdentClient::create_reply()
{
    std::string reply;

    outbuf_.clear();

    if (!get_local_info())
        return false;
    if (!get_peer_info())
        return false;

    if (client_type_ == HostNone || server_type_ == HostNone)
        return false;
    if (client_type_ != server_type_)
        return false;

    ParseState ps = parse_request();
    if (ps == ParseInvalid) {
        return false;
    } else if (ps == ParseBadPort) {
        reply = "ERROR:INVALID-PORT";
    } else if (ps == ParseServerPort || ps == ParseClientPort) {
        log_line("Request parse incomplete: should never happen.");
        return false;
    } else {
        Parse pa;
        int uid = -1;
        if (client_type_ == HostIP4)
            uid = pa.parse_tcp("/proc/net/tcp", server_address_, server_port_,
                               client_address_, client_port_);
        if (client_type_ == HostIP6)
            uid = pa.parse_tcp6("/proc/net/tcp6", server_address_, server_port_,
                                client_address_, client_port_);
        if (uid == -1) {
            if (gParanoid)
                reply = "ERROR:UNKNOWN-ERROR";
            else
                reply = "ERROR:NO-USER";
        } else {
            struct passwd *pw = getpwuid(uid);
            if (pw && pw->pw_dir) {
                std::string path(pw->pw_dir);
                path += "/.ident";
                if (pa.parse_cfg(path, server_address_, server_port_,
                                 client_address_, client_port_))
                    reply = pa.get_response(server_address_, server_port_,
                                            client_address_, client_port_);
            }
        }
        if (!reply.size()) {
            if (gParanoid)
                reply = "ERROR:UNKNOWN-ERROR";
            else
                reply = "ERROR:HIDDEN-USER";
        }
    }

    outbuf_ = reply;
    outbuf_ += "\r\n";
    log_line("(%s) %d,%d -> %s", client_address_pretty_.c_str(),
             server_port_, client_port_, reply.c_str());
    state_ = STATE_WAITOUT;
    schedule_write(fd_);
    return true;
}

// Returns false if the object needs to be destroyed by the caller.
// State can change: STATE_WAITOUT -> STATE_DONE
bool IdentClient::process_output()
{
    while (outbuf_.size()) {
        int written = write(fd_, outbuf_.c_str(), outbuf_.size());
        if (written == 0)
            break;
        if (written == -1) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            log_line("fd %i: write() error %s", strerror(errno));
            return false;
        }
        outbuf_.erase(0, written);
    }
    if (outbuf_.size() == 0) {
        state_ = STATE_DONE;
        return false;
    }
    return true;
}
