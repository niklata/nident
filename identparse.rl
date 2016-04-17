/* identparse.rl - ident client request handling
 *
 * (c) 2010-2013 Nicholas J. Kain <njkain at gmail dot com>
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

#include "identclient.hpp"

%%{
    machine ident_parser;
    action SPSt { spstart = p; }
    action SPEn {
        char pbuf[9] = {0};
        memcpy(pbuf, spstart, p - spstart);
        server_port_ = atoi(pbuf);
        if (server_port_ > 65535)
            return ParseBadPort;
    }
    action CPSt { cpstart = p; }
    action CPEn {
        char pbuf[9] = {0};
        memcpy(pbuf, cpstart, p - cpstart);
        client_port_ = atoi(pbuf);
        if (client_port_ > 65535)
            return ParseBadPort;
    }
    ws = [ \t];
    main := ws* (digit{1,5} > SPSt % SPEn) ws*
            ',' ws* (digit{1,5} > CPSt % CPEn) ws*;
}%%

%% write data;

// Returns ParseInvalid if the object needs to be destroyed by the caller.
IdentClient::ParseState IdentClient::parse_request()
{
    int cs = 0;
    const char *p = inbuf_.c_str();
    const char *pe = p + inbuf_.size();
    const char *eof = pe;
    const char *spstart, *cpstart;

    %% write init;
    %% write exec;

    if (cs >= ident_parser_first_final)
        return ParseDone;
    return ParseInvalid;
}

