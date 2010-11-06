/* identclient.hpp - ident client request handling
 * Time-stamp: <2010-11-06 08:48:31 nk>
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

#ifndef NK_IDENTCLIENT_H
#define NK_IDENTCLIENT_H

#include <string>
#include <netdb.h>

class IdentClient {
public:
    enum IdentClientState {
        STATE_WAITIN,
        STATE_GOTIN,
        STATE_WAITOUT,
        STATE_DONE
    };

    const int fd_;
    std::string inbuf_;
    std::string outbuf_;
    IdentClientState state_;

    struct in6_addr server_address_;
    struct in6_addr client_address_;
    std::string client_address_pretty_;

    int server_port_; // Port on the local machine this server is running on.
    int client_port_; // Port on the remote machine making the ident request.

    IdentClient(int fd);
    ~IdentClient();

    bool process_input();
    bool parse_request();
    bool create_reply();
    bool get_local_info();
    bool get_peer_info();
    bool process_output();
private:
    bool decipher_addr(const struct sockaddr_storage &addr,
                       struct in6_addr *addy, std::string *addyp,
                       const char *pstr);
};

extern unsigned int max_client_bytes;

#endif /* NK_IDENTCLIENT_H */
