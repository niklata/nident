/* identclient.cpp - ident client request handling
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

#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

#include <nk/format.hpp>

#include "identclient.hpp"
#include "parse.hpp"
#include "netlink.hpp"

namespace ba = boost::asio;

extern ba::io_service io_service;
extern Netlink *nlink;
extern bool gParanoid;
extern bool gChrooted;
extern int gflags_quiet;

unsigned int max_client_bytes = 128;

IdentClient::IdentClient(ba::ip::tcp::socket socket)
        : state_(STATE_WAITIN), tcp_socket_(std::move(socket)),
          writePending_(false)
{}

void IdentClient::do_read()
{
    auto sfd(shared_from_this());
    tcp_socket_.async_read_some
        (ba::buffer(inBytes_),
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             if (state_ != STATE_DONE && ec) {
                 fmt::print(stderr, "Client read error: {}\n",
                            boost::system::system_error(ec).what());
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
         });
}

void IdentClient::do_write()
{
    assert(!writePending_);
    writePending_ = true;
    auto sfd(shared_from_this());
    // State can change: STATE_WAITOUT -> STATE_DONE
    ba::async_write(
        tcp_socket_, ba::buffer(outbuf_),
        [this, sfd](const boost::system::error_code &ec,
                    std::size_t bytes_xferred)
        {
            writePending_ = false;
            if (ec) {
                fmt::print(stderr, "Client write error: {}\n",
                           boost::system::system_error(ec).what());
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

        });
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

    size_t loc = inbuf_.find('\n');
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

// Forms a reply and schedules a write.
// State can change: STATE_GOTIN -> STATE_WAITOUT
bool IdentClient::create_reply()
{
    std::string reply{"ERROR:UNKNOWN-ERROR"};

    outbuf_.clear();

    server_address_ = tcp_socket_.local_endpoint().address();
    client_address_ = tcp_socket_.remote_endpoint().address();

    if (server_address_.is_v6() != client_address_.is_v6())
        return false;

    ParseState ps = parse_request();
    int uid = -1;
    if (ps == ParseInvalid) {
        return false;
    } else if (ps == ParseBadPort) {
        reply = "ERROR:INVALID-PORT";
    } else if (ps == ParseServerPort || ps == ParseClientPort) {
        fmt::print(stderr, "Request parse incomplete: should never happen.\n");
        return false;
    } else {
        uid = nlink->get_tcp_uid(server_address_, server_port_,
                                 client_address_, client_port_);
        if (uid == -1) {
            if (!gParanoid)
                reply = "ERROR:NO-USER";
        } else {
            std::string path;
            if (!gChrooted) {
                struct passwd *pw = getpwuid(uid);
                if (pw && pw->pw_dir) {
                    path = fmt::format("{}/.ident", pw->pw_dir);
                }
            } else {
                path = fmt::format("/{}", uid);
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
        if (!gParanoid && !reply.size())
            reply = "ERROR:HIDDEN-USER";
    }

    outbuf_ = fmt::format("{},{}:{}\r\n", server_port_, client_port_, reply);
    write();
    if (!gflags_quiet) {
        fmt::print("({},{}) {},{} uid={} -> {}\n", server_address_.to_string(),
                   client_address_.to_string(), server_port_, client_port_,
                   uid, reply);
        std::fflush(stdout);
    }
    return true;
}

ClientListener::ClientListener(const ba::ip::tcp::endpoint &endpoint)
        : acceptor_(io_service), socket_(io_service)
{
    acceptor_.open(endpoint.protocol());
    acceptor_.set_option(ba::ip::tcp::acceptor::reuse_address(true));
    acceptor_.bind(endpoint);
    acceptor_.listen();
    start_accept();
}

void ClientListener::start_accept()
{
    acceptor_.async_accept
        (socket_,
         [this](const boost::system::error_code &ec)
         {
             if (ec)
                 return;
             auto conn = std::make_shared<IdentClient>(std::move(socket_));
             conn->start();
             start_accept();
         });
}
