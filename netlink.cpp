/* netlink.cpp - netlink abstraction
 *
 * (c) 2011-2012 Nicholas J. Kain <njkain at gmail dot com>
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

size_t Netlink::bc_size(size_t salen, size_t calen) const
{
    return 2 * sizeof(struct inet_diag_bc_op) +
           2 * sizeof (struct inet_diag_hostcond) + salen + calen;
}

// Returns the length of the message stored in bcbase or 0 on failure.
size_t Netlink::create_bc(char *bcbase, unsigned char *sabytes, size_t salen,
                          uint16_t sport, unsigned char *cabytes, size_t calen,
                          uint16_t dport) const
{
    if (!sabytes || (salen != 4 && salen != 16)) {
        std::cerr << "sabytes == NULL or salen size invalid" << std::endl;
        return 0;
    }
    if (!cabytes && (calen != 4 && calen != 16)) {
        std::cerr << "cabytes == NULL or calen size invalid" << std::endl;
        return 0;
    }

    const size_t blenp = bc_size(salen, calen);
    const size_t opsize = sizeof(struct inet_diag_bc_op);
    const size_t condsize = sizeof(struct inet_diag_hostcond);
    const size_t oplen0 = salen + opsize + condsize;
    const size_t oplen1 = calen + opsize + condsize;

    struct inet_diag_bc_op *op0 = (struct inet_diag_bc_op *)bcbase;
    op0->code = INET_DIAG_BC_S_COND;
    op0->yes = oplen0;
    op0->no = blenp + 4;
    struct inet_diag_hostcond *cond0 = (struct inet_diag_hostcond*)((char *)op0 + opsize);
    cond0->family = (salen == 16 ? AF_INET6 : AF_INET);
    cond0->port = sport;
    cond0->prefix_len = 0;
    memcpy(cond0->addr, sabytes, salen);

    struct inet_diag_bc_op *op1 = (struct inet_diag_bc_op *)((char *)bcbase + oplen0);
    op1->code = INET_DIAG_BC_D_COND;
    op1->yes = oplen1;
    op1->no = oplen1 + 4;
    struct inet_diag_hostcond *cond1 = (struct inet_diag_hostcond*)((char *)op1 + opsize);
    cond1->family = (calen == 16 ? AF_INET6 : AF_INET);
    cond1->port = dport;
    cond1->prefix_len = 0;
    memcpy(cond1->addr, cabytes, calen);

    return blenp;
}

bool Netlink::open(int socktype)
{
    if (fd_ != -1) {
        if (socktype_ == socktype) {
            return true;
        } else {
            close(fd_);
            fd_ = -1;
            socktype_ = -1;
        }
    }

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

bool Netlink::nlmsg_ok(const struct nlmsghdr *nlh, size_t len) const
{
    return len >= sizeof(struct nlmsghdr) &&
        nlh->nlmsg_len >= sizeof(struct nlmsghdr) &&
        nlh->nlmsg_len <= len;
}

#define NLK_ALIGNTO             4
#define NLK_ALIGN(len)          (((len)+NLK_ALIGNTO-1) & ~(NLK_ALIGNTO-1))
struct nlmsghdr *Netlink::nlmsg_next(const struct nlmsghdr *nlh, int &len)
{
    len -= NLK_ALIGN(nlh->nlmsg_len);
    return (struct nlmsghdr *)((char *)nlh + NLK_ALIGN(nlh->nlmsg_len));
}

#define NLK_RTM_NL_DATAMAX (sizeof(struct rtnl_link_stats)/sizeof(uint32_t))
bool Netlink::get_if_stats(const std::string &ifname, size_t *rx, size_t *tx)
{
    if (!open(NETLINK_ROUTE)) {
        std::cerr << "failed to create netlink socket" << std::endl;
        return false;
    }

    struct nlmsghdr *nlh;
    struct {
        struct nlmsghdr nlh;
        struct rtgenmsg g;
    } req;
    unsigned int this_seq = seq_++;
    memset(&req, 0, sizeof req);
    req.nlh.nlmsg_len = sizeof req;
    req.nlh.nlmsg_type = RTM_GETLINK;
    req.nlh.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
    req.nlh.nlmsg_pid = portid_;
    req.nlh.nlmsg_seq = this_seq;
    req.g.rtgen_family = RTM_GETLINK;
    send(fd_, (void*)&req, sizeof req, 0); // check errors

    char buf[8192];
    int rbytes = recv(fd_, buf, sizeof buf, 0);
    if (rbytes < 0) {
        std::cerr << "get_if_stats: recv() error: " << strerror(errno)
                  << std::endl;
        return false;
    }

  again:
    for (nlh = reinterpret_cast<struct nlmsghdr *>(buf);
         nlmsg_ok(nlh, rbytes); nlh = nlmsg_next(nlh, rbytes)) {
        if (nlh->nlmsg_pid != portid_) {
            std::cerr << "get_if_stats: bad portid: "
                      << nlh->nlmsg_pid << "!=" << portid_ << std::endl;
            continue;
        }
        if (nlh->nlmsg_seq != this_seq) {
            std::cerr << "get_if_stats: bad seq: " << nlh->nlmsg_seq
                      << " != " << this_seq << std::endl;
            continue;
        }

        if (nlh->nlmsg_type == RTM_NEWLINK) {
            struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
            struct rtattr *tb[IFLA_MAX+1] = {};

            // See if interface is down.
            if (!(ifi->ifi_flags & IFF_UP))
                continue;

            // Populate tb with the real stats data.
            size_t rta_size = nlh->nlmsg_len - sizeof(*nlh) - sizeof(*ifi);
            auto rta = IFLA_RTA(ifi);
            for (; RTA_OK(rta, rta_size); rta = RTA_NEXT(rta, rta_size)) {
                if ((rta->rta_type <= IFLA_MAX) && (!tb[rta->rta_type]))
                    tb[rta->rta_type] = rta;
            }

            // Sanity check the raw data.
            if (tb[IFLA_IFNAME] == NULL || tb[IFLA_STATS] == NULL)
                continue;

            // Skip if the interface name doesn't match.
            std::string name((char *)RTA_DATA(tb[IFLA_IFNAME]));
            if (ifname != name)
                continue;

            // idx: 0 = rxpkts, 1 = txpkts, 2 = rxbytes, 3 = txbytes
            uint32_t ival[NLK_RTM_NL_DATAMAX] = {};
            memcpy(ival, RTA_DATA(tb[IFLA_STATS]), sizeof ival);
            *rx = ival[2];
            *tx = ival[3];

            while (recv(fd_, buf, sizeof buf, MSG_DONTWAIT) >= 0);
            return true;
        }
    }
    if (recv(fd_, buf, sizeof buf, MSG_DONTWAIT) >= 0)
        goto again;
    return false;
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

    size_t salen, dalen;
    unsigned char *sabytes, *dabytes;
    if (sa.is_v4()) {
        salen = dalen = 4;
        sabytes = sa.to_v4().to_bytes().data();
        dabytes = da.to_v4().to_bytes().data();
    } else {
        salen = dalen = 16;
        sabytes = sa.to_v6().to_bytes().data();
        dabytes = da.to_v6().to_bytes().data();
    }
    size_t bclen = bc_size(salen, dalen);

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
    char bcbuf[bclen];
    memset(bcbuf, 0, sizeof bcbuf);
    create_bc(bcbuf, sabytes, salen, sp, dabytes, dalen, dp);
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
        return uid;
    }

    char buf[8192];
    iov[0].iov_base = buf;
    iov[0].iov_len = sizeof buf;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    int rbytes = recvmsg(fd_, &msg, MSG_WAITALL);
    if (rbytes < 0) {
        std::cerr << "get_tcp_uid: recvmsg() error: " << strerror(errno)
                  << std::endl;
        return uid;
    }

  again:
    for (nlh = reinterpret_cast<struct nlmsghdr *>(buf);
         nlmsg_ok(nlh, rbytes); nlh = nlmsg_next(nlh, rbytes)) {
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

        if (nlh->nlmsg_type == NLMSG_DONE)
            break;
        if (nlh->nlmsg_type == NLMSG_ERROR) {
            std::cerr << "get_tcp_uid: received NLMSG_ERROR reply" << std::endl;
            break;
        }

        if (nlh->nlmsg_type == TCPDIAG_GETSOCK) {
            struct inet_diag_msg *r = (struct inet_diag_msg *)NLMSG_DATA(nlh);

            unsigned short sport = ntohs(r->id.idiag_sport);
            unsigned short dport = ntohs(r->id.idiag_dport);
            if (sport != sp || dport != dp) {
                std::cerr << "get_tcp_uid: ports (sp,dp)=(" << sp << "," << dp << ") != (" << sport << "," << dport << ")" << std::endl;
                continue;
            }

            ba::ip::address saddr, daddr;
            ba::ip::address_v6 s6, d6;
            if (r->idiag_family == AF_INET) {
                ba::ip::address_v4::bytes_type s4b, d4b;
                memcpy(s4b.data(), r->id.idiag_src, 4);
                memcpy(d4b.data(), r->id.idiag_dst, 4);
                auto s4 = ba::ip::address_v4(s4b);
                auto d4 = ba::ip::address_v4(d4b);
                s6 = ba::ip::address_v6::v4_mapped(s4);
                d6 = ba::ip::address_v6::v4_mapped(d4);
            } else {
                ba::ip::address_v6::bytes_type s6b, d6b;
                memcpy(s6b.data(), r->id.idiag_src, 16);
                memcpy(d6b.data(), r->id.idiag_dst, 16);
                s6 = ba::ip::address_v6(s6b);
                d6 = ba::ip::address_v6(d6b);
            }
            if (sa.is_v4()) {
                if (s6.is_v4_mapped())
                    saddr = ba::ip::address(s6.to_v4());
                else
                    saddr = ba::ip::address(s6);
                if (d6.is_v4_mapped())
                    daddr = ba::ip::address(d6.to_v4());
                else
                    daddr = ba::ip::address(d6);
            } else {
                saddr = ba::ip::address(s6);
                daddr = ba::ip::address(d6);
            }
            if (saddr != sa) {
                std::cerr << "get_tcp_uid: v6 src addresses do not match: " << saddr << " != " << sa << std::endl;
                continue;
            }
            if (daddr != da) {
                std::cerr << "get_tcp_uid: v6 dst addresses do not match: " << daddr << " != " << da << std::endl;
                continue;
            }

            uid = r->idiag_uid;
            while (recvmsg(fd_, &msg, MSG_DONTWAIT) >= 0);
            break;
        }
    }
    iov[0].iov_base = buf;
    iov[0].iov_len = sizeof buf;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    if (uid == -1 && ((rbytes = recvmsg(fd_, &msg, MSG_DONTWAIT)) >= 0))
        goto again;
    return uid;
}
