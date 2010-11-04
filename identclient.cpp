/* identclient.cpp - ident client request handling
 * Time-stamp: <2010-11-04 00:11:25 nk>
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

#include <unistd.h>
#include <stdlib.h> // atoi
#include <string.h> // memset

#include "epoll.hpp"
#include "identclient.hpp"

extern "C" {
#include "log.h"
}

unsigned int max_client_bytes = 128;

IdentClient::IdentClient(int fd) : fd_(fd) {
    state_ = STATE_WAITIN;
    server_port_ = 0;
    client_port_ = 0;
    response_ = "ERROR";
    add_info_ = "NO-USER";
}

IdentClient::~IdentClient() {
    close(fd_);
    log_line("fd %d: destructor called", fd_);
}

// Returns false if the object needs to be destroyed by the caller.
// State can change: STATE_WAITIN -> STATE_GOTIN
bool IdentClient::process_input()
{
    if (state_ != STATE_WAITIN)
        return false;
    char buf[max_client_bytes];
    memset(buf, 0, sizeof buf);
    ssize_t len = 0;
    while (len < max_client_bytes) {
        ssize_t r = read(fd_, buf, sizeof buf);
        if (r == 0)
            break;
        if (r == -1) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            log_line("fd %i: read() error %d", fd_, strerror(errno));
            return false;
        }
        len += r;
    }
    for (int i = 0; i < len; ++i) {
        if (buf[i] == '\n' || buf[i] == '\r') {
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
                    server_port_ = atoi(sport.c_str());
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
        client_port_ = atoi(cport.c_str());
        state = ParseDone;
        return true;
    }
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

    // XXX: do real work for a real response
    std::stringstream ss;
    ss << server_port_ << "," << client_port_ << ":"
       << response_ << ":" << add_info_ << "\r\n";
    outbuf_ = ss.str();
    log_line("reply: %s", ss.str().c_str());
    state_ = STATE_WAITOUT;
    schedule_write(fd_);
    return true;
}

// Returns false if the object needs to be destroyed by the caller.
// State can change: STATE_WAITOUT -> STATE_DONE
bool IdentClient::process_output()
{
  repeat:
    int written = write(fd_, outbuf_.c_str(), outbuf_.size());
    if (written == -1) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            goto repeat;
        log_line("fd %i: write() error %s", strerror(errno));
        return false;
    }
    outbuf_.erase(0, written);
    if (outbuf_.size() == 0) {
        state_ = STATE_DONE;
        return false;
    }
    return true;
}
