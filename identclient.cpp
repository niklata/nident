/* identclient.cpp - ident client request handling
 * Time-stamp: <2010-11-06 01:26:21 nk>
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

#include "epoll.hpp"
#include "identclient.hpp"
#include "parse.hpp"

extern "C" {
#include "log.h"
}

unsigned int max_client_bytes = 128;

IdentClient::IdentClient(int fd) : fd_(fd) {
    state_ = STATE_WAITIN;
    server_port_ = -1;
    client_port_ = -1;
}

IdentClient::~IdentClient() {
    close(fd_);
    log_line("fd %d: destructor called", fd_);
}

// Returns false if the object needs to be destroyed by the caller.
// State can change: STATE_WAITIN -> STATE_GOTIN
bool IdentClient::process_input()
{
    if (state_ != STATE_WAITIN) {
        log_line("process_input: state is not STATE_WAITIN");
        return false;
    }
    char buf[max_client_bytes];
    memset(buf, 0, sizeof buf);
    ssize_t len = 0;
    while (len < max_client_bytes) {
        log_line("read(%d, %d, %d)", fd_, buf+len, (sizeof buf) - len);
        ssize_t r = read(fd_, buf + len, (sizeof buf) - len);
        log_line("r = %d", r);
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
        log_line("buf[%d] = %d", i, buf[i]);
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

// Returns false if the object needs to be destroyed by the caller.
bool IdentClient::parse_request()
{
    enum ParseState {
        ParseInvalid,
        ParseServerPort,
        ParseClientPort,
        ParseDone
    } state = ParseServerPort;
    int prev_idx = 0;
    size_t i;
    bool found_num = false;
    bool found_ws_after_num = false;
    for (i = 0; i < inbuf_.size(); ++i) {
        const char c = inbuf_.at(i);
        if (state == ParseServerPort) {
            switch (c) {
                case ' ':
                case '\t':
                    log_line("ws");
                    if (found_num)
                        found_ws_after_num = true;
                    continue;
                case ',': {
                    std::string sport = inbuf_.substr(prev_idx, i);
                    std::stringstream ss;
                    ss << sport;
                    ss >> server_port_;
                    state = ParseClientPort;
                    prev_idx = i + 1;
                    found_num = false;
                    found_ws_after_num = false;
                    log_line("sport: %d", server_port_);
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
                        log_line("!");
                        return false;
                    }
                    log_line("#");
                    continue;
                default:
                    state = ParseInvalid;
                    log_line("!");
                    return false;
            }
        } else if (state == ParseClientPort) {
            switch (c) {
                case ' ':
                case '\t':
                    log_line("ws");
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
                        log_line("!");
                        return false;
                    }
                    log_line("#");
                    continue;
                default:
                    state = ParseInvalid;
                    log_line("!");
                    return false;
            }
        }
    }
  eol:
    if (state == ParseClientPort && found_num) {
        log_line("... prev_idx: %d, i: %d", prev_idx, i);
        std::string cport = inbuf_.substr(prev_idx, i);
        std::stringstream ss;
        ss << cport;
        ss >> client_port_;
        state = ParseDone;
        return true;
    }
    return false;
}

bool IdentClient::decipher_addr(const struct sockaddr_storage &addr,
                                struct in6_addr *addy, const char *pstr)
{
    if (addr.ss_family == AF_INET) {
        char hoststr[32];
        struct sockaddr_in *s = (struct sockaddr_in *)&addr;
        int r;
        int port = ntohs(s->sin_port);
        if (!inet_ntop(AF_INET, &s->sin_addr, hoststr, sizeof hoststr)) {
            log_line("inet_ntop (ipv4): %s", strerror(errno));
            return false;
        }
        std::cout << pstr << " host: [" << hoststr << "]:" << port << "\n";
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
        int port = ntohs(s->sin6_port);
        if (!inet_ntop(AF_INET6, &s->sin6_addr, hoststr, sizeof hoststr)) {
            log_line("inet_ntop (ipv6): %s", strerror(errno));
            return false;
        }
        std::cout << pstr << " host: [" << hoststr << "]:" << port << "\n";
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
    if (decipher_addr(addr, &server_address_, "local"))
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
    if (decipher_addr(addr, &client_address_, "remote"))
        return true;
    else
        return false;
}

// Forms a reply and schedules a write.
// State can change: STATE_GOTIN -> STATE_WAITOUT
bool IdentClient::create_reply()
{
    outbuf_.clear();
    if (!parse_request()) {
        return false;
    }
    log_line("serverport: %i\t clientport: %i", server_port_, client_port_);

    Parse pa;
    pa.parse_tcp("/proc/net/tcp");
    pa.parse_tcp6("/proc/net/tcp6");
    pa.parse_cfg("/home/njk/.ident");

    if (!get_local_info())
        return false;
    if (!get_peer_info())
        return false;

    std::string reply = pa.get_response(server_address_, server_port_,
                                        client_address_, client_port_);

    outbuf_ = reply;
    outbuf_ += "\r\n";
    log_line("reply: %s", outbuf_.c_str());
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
