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

Netlink::Netlink(bool v4only) : v4only_(v4only), fd_(-1), socktype_(-1) {}
Netlink::~Netlink() { close(fd_); }

size_t Netlink::bc_size() const
{
    const size_t addrsiz = v4only_ ? 4 : 16; // bytes
    return 2 * (sizeof(struct inet_diag_bc_op)
                + sizeof(struct inet_diag_hostcond) + addrsiz);
}

// Returns the length of the message stored in bcbase or 0 on failure.
size_t Netlink::create_bc(char *bcbase, uint16_t sport, uint16_t dport) const
{
    const size_t blenp = bc_size();
    const size_t addrsiz = v4only_ ? 4 : 16; // bytes
    const size_t opsize = sizeof(struct inet_diag_bc_op);
    const size_t condsize = sizeof(struct inet_diag_hostcond) + addrsiz;
    const size_t oplen0 = opsize + condsize;
    const size_t oplen1 = opsize + condsize;
    const uint8_t afam = (v4only_ ? AF_INET : AF_INET6);

    struct inet_diag_bc_op *op0 = (struct inet_diag_bc_op *)bcbase;
    op0->code = INET_DIAG_BC_S_COND;
    op0->yes = oplen0;
    op0->no = blenp + 4;
    struct inet_diag_hostcond *cond0 = (struct inet_diag_hostcond*)((char *)op0 + opsize);
    cond0->family = afam;
    cond0->port = sport;
    cond0->prefix_len = 0;

    struct inet_diag_bc_op *op1 = (struct inet_diag_bc_op *)((char *)bcbase + oplen0);
    op1->code = INET_DIAG_BC_D_COND;
    op1->yes = oplen1;
    op1->no = oplen1 + 4;
    struct inet_diag_hostcond *cond1 = (struct inet_diag_hostcond*)((char *)op1 + opsize);
    cond1->family = afam;
    cond1->port = dport;
    cond1->prefix_len = 0;

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
    int rbytes = recv(fd_, buf, sizeof buf, MSG_WAITALL);
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

        if (nlh->nlmsg_type == NLMSG_DONE)
            break;
        if (nlh->nlmsg_type == NLMSG_ERROR) {
            std::cerr << "get_if_stats: received NLMSG_ERROR reply" << std::endl;
            break;
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
    if ((rbytes = recv(fd_, buf, sizeof buf, MSG_DONTWAIT)) >= 0)
        goto again;
    return false;
}

#if 0
static bool effective_v4(ba::ip::address a)
{
    if (a.is_v4())
        return true;
    auto a6 = a.to_v6();
    if (a6.is_v4_mapped() || a6.is_v4_compatible())
        return true;
    return false;
}
#endif

// v6 -> v4 is VALID IIF v6ismapped|v6iscompat
static bool v4_addreq(const ba::ip::address &a, const ba::ip::address_v4 &v, bool src)
{
    if (a.is_v4()) {
        if (a != v) {
            std::cout << "v4_addreq: " << (src?"src":"dst") << " addresses do not match - a/v4 [" << a << "] != v/v4 [" << v << "]\n";
            return false;
        }
        return true;
    }

    auto a6 = a.to_v6();
    bool a6mapped(a6.is_v4_mapped()), a6compat(a6.is_v4_compatible());
    if (a6mapped || a6compat) {
        ba::ip::address_v4 a4;
        try {
            a4 = a6.to_v4();
        } catch (const std::bad_cast &) { goto fail; }
        if (a4 == v)
            return true;
        std::cout << "v4_addreq: " << (src?"src":"dst") << " addresses do not match - a/v6" << (a6mapped?"m":"c") << " [" << a << "] != v/v4 [" << v << "]\n";
        return false;
    }
fail:
    std::cout << "v4_addreq: " << (src?"src":"dst") << " addresses do not match - a/v6 [" << a << "] != v/v4 [" << v << "]\n";
    return false;
}

static bool v6_addreq(const ba::ip::address &a, const ba::ip::address_v6 &v, bool src)
{
    if (a.is_v6()) {
        auto a6 = a.to_v6();
        bool amapped(a6.is_v4_mapped()), acompat(a6.is_v4_compatible());
        if (amapped || acompat) {
            ba::ip::address_v4 a4;
            try {
                a4 = a6.to_v4();
            } catch (const std::bad_cast &) { goto normal_test; }
            bool vmapped(v.is_v4_mapped()), vcompat(v.is_v4_compatible());
            if (vmapped || vcompat) {
                ba::ip::address_v4 v4;
                try {
                    v4 = v.to_v4();
                } catch (const std::bad_cast &) { goto fail2; }
                if (a4 == v4)
                    return true;
                std::cout << "v6_addreq: " << (src?"src":"dst") << " addresses do not match - a/v4" << (amapped?"m":"c") << " [" << a << "] != v/v4" << (vmapped?"m":"c") << " [" << v << "]\n";
                return false;
            }
fail2:
            std::cout << "v6_addreq: " << (src?"src":"dst") << " addresses do not match - a/v4" << (amapped?"m":"c") << " [" << a << "] != v/v4 [" << v << "]\n";
            return false;
        }
normal_test:
        if (a != v) {
            std::cout << "v6_addreq: " << (src?"src":"dst") << " addresses do not match - a/v6 [" << a << "] != v/v6 [" << v << "]\n";
            return false;
        }
        return true;
    }
    bool vmapped(v.is_v4_mapped()), vcompat(v.is_v4_compatible());
    if (vmapped || vcompat) {
        ba::ip::address_v4 v4;
        try {
            v4 = v.to_v4();
        } catch (const std::bad_cast &) { goto fail; }
        if (a == v4)
            return true;
        std::cout << "v6_addreq: " << (src?"src":"dst") << " addresses do not match - a/v4 [" << a << "] != v/v6" << (vmapped?"m":"c") << " [" << v << "]\n";
        return false;
    }
fail:
    std::cout << "v6_addreq: " << (src?"src":"dst") << " addresses do not match - a/v4 [" << a << "] != v/v6 [" << v << "]\n";
    return false;
}

int Netlink::get_tcp_uid(ba::ip::address sa, unsigned short sp,
                         ba::ip::address da, unsigned short dp)
{
    int uid = -1;

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
    req.r.idiag_family = (v4only_ ? AF_INET : AF_INET6);
    req.r.idiag_states = TCPF_ESTABLISHED;
    req.r.idiag_ext = (1 << (INET_DIAG_INFO-1));

    iov[0].iov_base = &req;
    iov[0].iov_len = sizeof req;
    size_t bclen = bc_size();
    char bcbuf[bclen];
    memset(bcbuf, 0, sizeof bcbuf);
    create_bc(bcbuf, sp, dp);
    rta.rta_type = INET_DIAG_REQ_BYTECODE;
    rta.rta_len = RTA_LENGTH(bclen);
    iov[1].iov_base = &rta;
    iov[1].iov_len = sizeof rta;
    iov[2].iov_base = bcbuf;
    iov[2].iov_len = bclen;
    req.nlh.nlmsg_len += rta.rta_len;

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

            if (r->idiag_family == AF_INET6) {
                ba::ip::address_v6::bytes_type s6b, d6b;
                memcpy(s6b.data(), r->id.idiag_src, 16);
                memcpy(d6b.data(), r->id.idiag_dst, 16);
                auto rs = ba::ip::address_v6(s6b);
                auto rd = ba::ip::address_v6(d6b);
                if (!v6_addreq(sa, rs, true))
                    continue;
                if (!v6_addreq(da, rd, false))
                    continue;
            } else {
                ba::ip::address_v4::bytes_type s4b, d4b;
                memcpy(s4b.data(), r->id.idiag_src, 4);
                memcpy(d4b.data(), r->id.idiag_dst, 4);
                auto rs = ba::ip::address_v4(s4b);
                auto rd = ba::ip::address_v4(d4b);
                if (!v4_addreq(sa, rs, true))
                    continue;
                if (!v4_addreq(da, rd, false))
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
