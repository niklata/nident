/* identclient.hpp - ident client request handling
 * Time-stamp: <2011-03-27 00:58:18 nk>
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

#ifndef NK_IDENTCLIENT_H
#define NK_IDENTCLIENT_H

#include <string>
#include <netdb.h>

#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <boost/enable_shared_from_this.hpp>

class IdentClient
    : public boost::enable_shared_from_this<IdentClient>
{
public:
    enum IdentClientState {
        STATE_WAITIN,
        STATE_GOTIN,
        STATE_WAITOUT,
        STATE_DONE
    };

    IdentClient(boost::asio::io_service &io_service);

    void start() { do_read(); }
    boost::asio::ip::tcp::socket &socket() { return tcp_socket_; }

private:
    enum ParseState {
        ParseInvalid,
        ParseBadPort,
        ParseServerPort,
        ParseClientPort,
        ParseDone
    };

    IdentClientState state_;
    boost::asio::ip::tcp::socket tcp_socket_;
    boost::array<char, 4096> inBytes_;
    std::string inbuf_;
    bool writePending_;
    std::string outbuf_;

    boost::asio::ip::address server_address_;
    boost::asio::ip::address client_address_;

    int server_port_; // Port on the local machine this server is running on.
    int client_port_; // Port on the remote machine making the ident request.

    void do_read();
    void do_write();
    void read_handler(const boost::system::error_code &ec,
                      std::size_t bytes_xferred);
    void write_handler(const boost::system::error_code &ec,
                       std::size_t bytes_xferred);
    bool process_input();
    bool create_reply();
    void write();

    ParseState parse_request();
};

class ClientListener
{
public:
    ClientListener(const boost::asio::ip::tcp::endpoint &endpoint);
    const boost::asio::ip::tcp::acceptor &socket() { return acceptor_; }
private:
    boost::asio::ip::tcp::acceptor acceptor_;

    void start_accept();
    void accept_handler(boost::shared_ptr<IdentClient> conn,
                        const boost::system::error_code &ec);
};

extern unsigned int max_client_bytes;

#endif /* NK_IDENTCLIENT_H */
