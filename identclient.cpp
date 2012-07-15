/* identclient.cpp - ident client request handling
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

#include <sstream>
#include <iostream>

#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>

#include "identclient.hpp"
#include "parse.hpp"
#include "netlink.hpp"

extern "C" {
#include "log.h"
}

namespace ba = boost::asio;

extern ba::io_service io_service;
extern Netlink *nlink;
extern bool gParanoid;
extern bool gChrooted;

unsigned int max_client_bytes = 128;

IdentClient::IdentClient(ba::io_service &io_service)
        : tcp_socket_(io_service)
{
    state_ = STATE_WAITIN;
    writePending_ = false;
}

void IdentClient::do_read()
{
    tcp_socket_.async_read_some
        (ba::buffer(inBytes_),
         boost::bind(&IdentClient::read_handler, shared_from_this(),
                     ba::placeholders::error,
                     ba::placeholders::bytes_transferred));
}

void IdentClient::read_handler(const boost::system::error_code &ec,
                                    std::size_t bytes_xferred)
{
    if (state_ != STATE_DONE && ec) {
        std::cerr << "Client read error: "
                  << boost::system::system_error(ec).what() << std::endl;
        return;
    }
    if (!bytes_xferred)
        return;
    inbuf_.append(inBytes_.data(), bytes_xferred);
    if (!process_input()) {
        state_ = STATE_DONE;
        tcp_socket_.cancel();
        tcp_socket_.close();
        return;
    }
    do_read();
}

void IdentClient::do_write()
{
    assert(!writePending_);
    writePending_ = true;
    ba::async_write(
        tcp_socket_, ba::buffer(outbuf_),
        boost::bind(&IdentClient::write_handler, shared_from_this(),
                    ba::placeholders::error,
                    ba::placeholders::bytes_transferred));
}

// State can change: STATE_WAITOUT -> STATE_DONE
void IdentClient::write_handler(const boost::system::error_code &ec,
                                     std::size_t bytes_xferred)
{
    writePending_ = false;
    if (ec) {
        std::cerr << "Client write error: "
                  << boost::system::system_error(ec).what() << std::endl;
        return;
    }
    outbuf_.erase(0, bytes_xferred);
    if (outbuf_.size())
        do_write();
    else {
        state_ = STATE_DONE;
        tcp_socket_.cancel();
        tcp_socket_.close();
    }
}

void IdentClient::write()
{
    if (!writePending_ && state_ == STATE_GOTIN) {
        state_ = STATE_WAITOUT;
        do_write();
    }
}

// Returns false if the object needs to be destroyed by the caller.
// State can change: STATE_WAITIN -> STATE_GOTIN
bool IdentClient::process_input()
{
    // Only one request per session is answered.
    if (state_ != STATE_WAITIN)
        return false;

    // See if client flooded us over several iterations of process_input().
    if (inbuf_.size() > max_client_bytes)
        return false;

    size_t loc = inbuf_.find_first_of("\r\n");
    if (loc != std::string::npos) {
        inbuf_.erase(loc);
        state_ = STATE_GOTIN;
    }

    if (state_ == STATE_GOTIN) {
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
                    if (server_port_ < 1 || server_port_ > 65535)
                        return ParseBadPort;
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
                    if (found_ws_after_num)
                        return ParseInvalid;
                    if (++sp_len > 5)
                        return ParseBadPort;
                    continue;
                default:
                    return ParseInvalid;
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
                    if (found_ws_after_num)
                        return ParseInvalid;
                    if (++cp_len > 5)
                        return ParseBadPort;
                    continue;
                default:
                    return ParseInvalid;
            }
        }
    }
  eol:
    if (state == ParseClientPort && found_num) {
        std::string cport = inbuf_.substr(prev_idx, i);
        std::stringstream ss;
        ss << cport;
        ss >> client_port_;
        if (client_port_ < 1 || client_port_ > 65535)
            return ParseBadPort;
        return ParseDone;
    }
    return ParseInvalid;
}

// Forms a reply and schedules a write.
// State can change: STATE_GOTIN -> STATE_WAITOUT
bool IdentClient::create_reply()
{
    std::string reply;

    outbuf_.clear();

    server_address_ = tcp_socket_.local_endpoint().address();
    client_address_ = tcp_socket_.remote_endpoint().address();

    if (server_address_.is_v6() != client_address_.is_v6())
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
        int uid = nlink->get_tcp_uid(server_address_, server_port_,
                                     client_address_, client_port_);
        if (uid == -1) {
            if (gParanoid)
                reply = "ERROR:UNKNOWN-ERROR";
            else
                reply = "ERROR:NO-USER";
        } else {
            std::string path;
            if (!gChrooted) {
                struct passwd *pw = getpwuid(uid);
                if (pw && pw->pw_dir) {
                    path = pw->pw_dir;
                    path += "/.ident";
                }
            } else {
                path = "/";
                path += boost::lexical_cast<std::string>(uid);
            }
            if (path.size()) {
                Parse pa;
                if (pa.parse_cfg(path, server_address_, server_port_,
                                 client_address_, client_port_))
                    reply = pa.get_response(server_address_, server_port_,
                                            client_address_, client_port_,
                                            uid);
            }
        }
        if (!reply.size()) {
            if (gParanoid)
                reply = "ERROR:UNKNOWN-ERROR";
            else
                reply = "ERROR:HIDDEN-USER";
        }
    }

    std::stringstream ss;
    ss << server_port_ << "," << client_port_ << ":" << reply;
    ss >> outbuf_;
    outbuf_ += "\r\n";
    write();
    log_line("(%s) %d,%d -> %s", client_address_.to_string().c_str(),
             server_port_, client_port_, reply.c_str());
    return true;
}

ClientListener::ClientListener(const ba::ip::tcp::endpoint &endpoint)
        : acceptor_(io_service)
{
    acceptor_.open(endpoint.protocol());
    acceptor_.set_option(ba::ip::tcp::acceptor::reuse_address(true));
    acceptor_.bind(endpoint);
    acceptor_.listen();
    start_accept();
}

void ClientListener::start_accept()
{
    boost::shared_ptr<IdentClient> conn(
        new IdentClient(acceptor_.get_io_service()));
    acceptor_.async_accept(conn->socket(), boost::bind(
                               &ClientListener::accept_handler, this,
                               conn, ba::placeholders::error));
}

void ClientListener::accept_handler(boost::shared_ptr<IdentClient> conn,
                                    const boost::system::error_code &ec)
{
    if (ec)
        return;
    conn->start();
    start_accept();
}
