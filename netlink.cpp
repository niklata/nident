/* netlink.cpp - netlink abstraction
 * Time-stamp: <2011-03-29 03:26:02 nk>
 *
 * (c) 2011 Nicholas J. Kain <njkain at gmail dot com>
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

#include <iostream>
#include <unistd.h>
#include "netlink.hpp"
namespace ba = boost::asio;

Netlink::Netlink() {
    fd_ = -1;
    socktype_ = -1;
}

Netlink::~Netlink() {
    close(fd_);
}

int Netlink::bc_size(int salen, int calen) const
{
    return 12 + 2 * sizeof (struct inet_diag_hostcond) + salen + calen;
}

// Returns the length of the message stored in bcbase or 0 on failure.
int Netlink::create_bc(char *bcbase, unsigned char *sabytes, int salen,
                       uint16_t sport, unsigned char *cabytes, int calen,
                       uint16_t dport)
{
    if (!sabytes || (salen != 4 && salen != 16))
        return 0;
    if (!cabytes && (calen != 4 && calen != 16))
        return 0;

    int blenp = bc_size(salen, calen);
    struct inet_diag_bc_op *op0 = (struct inet_diag_bc_op *)bcbase;
    int oplen0 = salen + 4 + sizeof (struct inet_diag_hostcond);
    op0->code = INET_DIAG_BC_S_COND;
    op0->yes = oplen0;
    op0->no = oplen0 + 4;
    struct inet_diag_hostcond *cond0 = (struct inet_diag_hostcond*)(bcbase + 4);
    cond0->family = (salen == 16 ? AF_INET6 : AF_INET);
    cond0->port = sport;
    cond0->prefix_len = salen * 8;
    memcpy(cond0->addr, sabytes, salen);
    struct inet_diag_bc_op *link0 = (struct inet_diag_bc_op *)(((char *)op0) + op0->yes);
    link0->code = INET_DIAG_BC_JMP;
    link0->yes = 4;
    link0->no = blenp - (((char *)link0) - ((char *)op0));

    struct inet_diag_bc_op *op1 = (struct inet_diag_bc_op *)(((char *)link0) + 4);
    int oplen1 = calen + 4 + sizeof (struct inet_diag_hostcond);
    op1->code = INET_DIAG_BC_D_COND;
    op1->yes = oplen1;
    op1->no = oplen1 + 4;
    struct inet_diag_hostcond *cond1 = (struct inet_diag_hostcond*)(((char *)op1) + 4);
    cond1->family = (calen == 16 ? AF_INET6 : AF_INET);
    cond1->port = dport;
    cond1->prefix_len = calen * 8;
    memcpy(cond1->addr, cabytes, calen);

    return (op1 + op1->yes) - op0;
}

bool Netlink::open(int socktype)
{
    std::cerr << "entered Netlink::open()\n";
    if (fd_ != -1) {
        if (socktype_ == socktype) {
            std::cerr << "Netlink::open(): existing socket OK\n";
            return true;
        } else {
            std::cerr << "Netlink::open(): existing socket destroyed\n";
            close(fd_);
            fd_ = -1;
            socktype_ = -1;
        }
    }
    std::cerr << "Netlink::open(): opening new socket\n";

    int ret = socket(AF_NETLINK, SOCK_RAW, socktype);
    if (ret < 0) {
        std::cerr << "Netlink: socket() error: " << strerror(errno) << std::endl;
        return false;
    }
    fd_ = ret;
    socktype_ = socktype;

    struct sockaddr_nl nladdr;
    socklen_t nladdr_len = sizeof nladdr;
    memset(&nladdr, 0, sizeof nladdr);
    nladdr.nl_family = AF_NETLINK;

    if (bind(fd_, (struct sockaddr *)&nladdr, sizeof nladdr) < 0) {
        std::cerr << "get_tcp_uid: bind() error: " << strerror(errno)
                  << std::endl;
        goto fail;
    }
    if (getsockname(fd_, (struct sockaddr *)&nladdr, &nladdr_len) < 0) {
        std::cerr << "get_tcp_uid: getsockname() error: " << strerror(errno)
                  << std::endl;
        goto fail;
    }
    if (nladdr_len != sizeof nladdr) {
        std::cerr << "get_tcp_uid: getsockname address length mismatch"
                  << std::endl;
        goto fail;
    }
    if (nladdr.nl_family != AF_NETLINK) {
        std::cerr << "get_tcp_uid: getsockname address type mismatch"
                  << std::endl;
        goto fail;
    }

    portid_ = nladdr.nl_pid;
    seq_ = time(NULL);

    return true;
  fail:
    close(fd_);
    fd_ = -1;
    return false;
}

bool Netlink::nlmsg_ok(const struct nlmsghdr *nlh, int len) const
{
    return len >= (int)sizeof(struct nlmsghdr) &&
        nlh->nlmsg_len >= sizeof(struct nlmsghdr) &&
        (int)nlh->nlmsg_len <= len;
}

#define NLK_ALIGNTO             4
#define NLK_ALIGN(len)          (((len)+NLK_ALIGNTO-1) & ~(NLK_ALIGNTO-1))
struct nlmsghdr *Netlink::nlmsg_next(const struct nlmsghdr *nlh, int &len)
{
    len -= NLK_ALIGN(nlh->nlmsg_len);
    return (struct nlmsghdr *)((char *)nlh + NLK_ALIGN(nlh->nlmsg_len));
}

int Netlink::get_tcp_uid(ba::ip::address sa, unsigned short sp,
                         ba::ip::address da, unsigned short dp)
{
    int uid = -1;
    if (sa.is_v6() != da.is_v6()) {
        std::cerr << "saddr and daddr must both be IPv4 or both be IPv6"
                  << std::endl;
        return uid;
    }

    int salen, dalen;
    bool sa6mapped = false, da6mapped = false;
    if (sa.is_v4()) {
        salen = dalen = 4;
    } else {
        sa6mapped = sa.to_v6().is_v4_mapped();
        da6mapped = da.to_v6().is_v4_mapped();
        salen = sa6mapped ? 4 : 16;
        dalen = da6mapped ? 4 : 16;
    }
    int bclen = bc_size(salen, dalen);

    if (!open(NETLINK_INET_DIAG)) {
        std::cerr << "failed to create netlink socket" << std::endl;
        return uid;
    }

    struct nlmsghdr *nlh;
    struct {
        struct nlmsghdr nlh;
        struct inet_diag_req r;
    } req;
    struct iovec iov[3];
    struct msghdr msg;
    struct rtattr rta;
    unsigned int this_seq = seq_++;
    std::cout << "this seq = " << this_seq << std::endl;

    struct sockaddr_nl nladdr;
    memset(&nladdr, 0, sizeof nladdr);
    nladdr.nl_family = AF_NETLINK;

    req.nlh.nlmsg_len = sizeof req;
    req.nlh.nlmsg_type = TCPDIAG_GETSOCK;
    req.nlh.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
    req.nlh.nlmsg_pid = portid_;
    req.nlh.nlmsg_seq = this_seq;
    memset(&req.r, 0, sizeof req.r);
    req.r.idiag_family = AF_INET;
    req.r.idiag_states = TCPF_ESTABLISHED;
    req.r.idiag_ext = (1 << (INET_DIAG_INFO-1));

    iov[0].iov_base = &req;
    iov[0].iov_len = sizeof req;
    char *bcbuf = new char[bclen];
    memset(bcbuf, 0, bclen);
    if (sa.is_v4()) {
        create_bc(bcbuf, sa.to_v4().to_bytes().data(), salen, sp,
                  da.to_v4().to_bytes().data(), dalen, dp);
    } else {
        auto sb = sa.to_v6().is_v4_mapped() ?
            sa.to_v6().to_v4().to_bytes().data() : sa.to_v6().to_bytes().data();
        auto db = da.to_v6().is_v4_mapped() ?
            da.to_v6().to_v4().to_bytes().data() : da.to_v6().to_bytes().data();
        create_bc(bcbuf, sb, salen, sp, db, dalen, dp);
    }
    rta.rta_type = INET_DIAG_REQ_BYTECODE;
    rta.rta_len = RTA_LENGTH(bclen);
    iov[1].iov_base = &rta;
    iov[1].iov_len = sizeof rta;
    iov[2].iov_base = bcbuf;
    iov[2].iov_len = bclen;
    req.nlh.nlmsg_len += RTA_LENGTH(bclen);

    memset(&msg, 0, sizeof msg);
    msg.msg_name = (void*)&nladdr;
    msg.msg_namelen = sizeof nladdr;
    msg.msg_iov = iov;
    msg.msg_iovlen = 3;

    if (sendmsg(fd_, &msg, 0) < 0) {
        std::cerr << "get_tcp_uid: sendmsg() error: " << strerror(errno)
                  << std::endl;
        delete[] bcbuf;
        return uid;
    }
    delete[] bcbuf;

    char buf[8192];
    iov[0].iov_base = buf;
    iov[0].iov_len = sizeof buf;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    int rbytes = recvmsg(fd_, &msg, 0);
    if (rbytes < 0) {
        std::cerr << "get_tcp_uid: recvmsg() error: " << strerror(errno)
                  << std::endl;
        return uid;
    }

  again:
    for (nlh = reinterpret_cast<struct nlmsghdr *>(buf);
         nlmsg_ok(nlh, rbytes); nlh = nlmsg_next(nlh, rbytes)) {
        std::cerr << "Got a netlink reply!\n";
        if (nlh->nlmsg_pid != portid_) {
            std::cerr << "get_tcp_uid: bad portid: "
                      << nlh->nlmsg_pid << "!=" << portid_ << std::endl;
            continue;
        }
        if (nlh->nlmsg_seq != this_seq) {
            std::cerr << "get_tcp_uid: bad seq: " << nlh->nlmsg_seq
                      << " != " << this_seq << std::endl;
            continue;
        }
        std::cerr << "  -> sequence (" << this_seq << ") and portid passed\n";

        if (nlh->nlmsg_type == TCPDIAG_GETSOCK) {
            struct inet_diag_msg *r = (struct inet_diag_msg *)NLMSG_DATA(nlh);

            std::cerr << "  -> message type is TCPDIAG_GETSOCK\n";

            unsigned short sport = ntohs(r->id.idiag_sport);
            unsigned short dport = ntohs(r->id.idiag_dport);
            if (sport != sp || dport != dp) {
                std::cerr << "get_tcp_uid: ports do not match " << std::endl;
                continue;
            }
            ba::ip::address saddr, daddr;
            if (r->idiag_family == AF_INET) {
                ba::ip::address_v4::bytes_type s4b, d4b;
                memcpy(s4b.data(), r->id.idiag_src, 4);
                memcpy(d4b.data(), r->id.idiag_dst, 4);
                auto s4 = ba::ip::address_v4(s4b);
                auto d4 = ba::ip::address_v4(d4b);
                saddr = ba::ip::address(s4);
                daddr = ba::ip::address(d4);
                if (sa6mapped) {
                    auto sa4 = sa.to_v6().to_v4();
                    if (sa4 != s4) {
                        std::cerr << "get_tcp_uid: v4-mapped src addresses do not match\n";
                        continue;
                    }
                } else if (saddr != sa) {
                    std::cerr << "get_tcp_uid: v4 src addresses do not match\n";
                    continue;
                }
                if (da6mapped) {
                    auto da4 = da.to_v6().to_v4();
                    if (da4 != d4) {
                        std::cerr << "get_tcp_uid: v4-mapped dst addresses do not match\n";
                        continue;
                    }
                } else if (daddr != da) {
                    std::cerr << "get_tcp_uid: v4 dst addresses do not match\n";
                    continue;
                }
            } else {
                ba::ip::address_v6::bytes_type s6b, d6b;
                memcpy(s6b.data(), r->id.idiag_src, 16);
                memcpy(d6b.data(), r->id.idiag_dst, 16);
                saddr = ba::ip::address(ba::ip::address_v6(s6b));
                daddr = ba::ip::address(ba::ip::address_v6(s6b));
                if (saddr != sa) {
                    std::cerr << "get_tcp_uid: v6 src addresses do not match\n";
                    continue;
                }
                if (daddr != da) {
                    std::cerr << "get_tcp_uid: v6 dst addresses do not match\n";
                    continue;
                }
            }
            uid = r->idiag_uid;
            std::cout << "src: " << saddr << ":" << sport << " dst: "
                      << daddr << ":" << dport << std::endl;
            while (recvmsg(fd_, &msg, MSG_DONTWAIT) >= 0);
            break;
        }
    }
    if (uid == -1 && (recvmsg(fd_, &msg, MSG_DONTWAIT) >= 0))
        goto again;
    return uid;
}
