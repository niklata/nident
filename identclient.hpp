/* identclient.hpp - ident client request handling
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

#ifndef NK_IDENTCLIENT_H
#define NK_IDENTCLIENT_H

#include <string>
#include <memory>
#include <netdb.h>

#include <asio.hpp>

class IdentClient
    : public std::enable_shared_from_this<IdentClient>
{
public:
    enum IdentClientState {
        STATE_WAITIN,
        STATE_GOTIN,
        STATE_WAITOUT,
        STATE_DONE
    };

    IdentClient(asio::ip::tcp::socket socket);
    IdentClient(const IdentClient &) = delete;
    IdentClient& operator=(const IdentClient &) = delete;

    void start() { do_read(); }

private:
    enum ParseState {
        ParseInvalid,
        ParseBadPort,
        ParseServerPort,
        ParseClientPort,
        ParseDone
    };

    IdentClientState state_;
    asio::ip::tcp::socket tcp_socket_;
    std::array<char, 64> inBytes_;
    std::string inbuf_;
    bool writePending_;
    std::string outbuf_;

    asio::ip::address server_address_;
    asio::ip::address client_address_;

    int server_port_; // Port on the local machine this server is running on.
    int client_port_; // Port on the remote machine making the ident request.

    void do_read();
    void do_write();
    bool process_input();
    bool create_reply();
    void write();

    ParseState parse_request();
};

class ClientListener
{
public:
    ClientListener(const asio::ip::tcp::endpoint &endpoint);
    ClientListener(const ClientListener &) = delete;
    ClientListener& operator=(const ClientListener &) = delete;
    const asio::ip::tcp::acceptor &socket() { return acceptor_; }
private:
    asio::ip::tcp::acceptor acceptor_;
    asio::ip::tcp::socket socket_;

    void start_accept();
};

extern unsigned int max_client_bytes;

#endif /* NK_IDENTCLIENT_H */
