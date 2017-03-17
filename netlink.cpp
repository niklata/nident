/* netlink.cpp - netlink abstraction
 *
 * (c) 2011-2016 Nicholas J. Kain <njkain at gmail dot com>
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
#include "netlink.hpp"
#include <fmt/format.h>
#include <fmt/ostream.h>

Netlink::Netlink(bool v4only) : v4only_(v4only), fd_(-1), socktype_(-1),
    portid_(0), seq_(0) {}
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

    struct inet_diag_bc_op *op0 = (struct inet_diag_bc_op *)bcbase;
    op0->code = INET_DIAG_BC_S_COND;
    op0->yes = oplen0;
    op0->no = blenp + 4;
    struct inet_diag_hostcond *cond0 = (struct inet_diag_hostcond*)((char *)op0 + opsize);
    cond0->port = sport;
    cond0->prefix_len = 0;

    struct inet_diag_bc_op *op1 = (struct inet_diag_bc_op *)((char *)bcbase + oplen0);
    op1->code = INET_DIAG_BC_D_COND;
    op1->yes = oplen1;
    op1->no = oplen1 + 4;
    struct inet_diag_hostcond *cond1 = (struct inet_diag_hostcond*)((char *)op1 + opsize);
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
        fmt::print(stderr, "Netlink: socket() error: {}\n", strerror(errno));
        return false;
    }
    fd_ = ret;
    socktype_ = socktype;

    struct sockaddr_nl nladdr;
    socklen_t nladdr_len = sizeof nladdr;
    memset(&nladdr, 0, sizeof nladdr);
    nladdr.nl_family = AF_NETLINK;

    if (bind(fd_, (struct sockaddr *)&nladdr, sizeof nladdr) < 0) {
        fmt::print(stderr, "get_tcp_uid: bind() error: {}\n", strerror(errno));
        goto fail;
    }
    if (getsockname(fd_, (struct sockaddr *)&nladdr, &nladdr_len) < 0) {
        fmt::print(stderr, "get_tcp_uid: getsockname() error: {}\n",
                   strerror(errno));
        goto fail;
    }
    if (nladdr_len != sizeof nladdr) {
        fmt::print(stderr, "get_tcp_uid: getsockname address length mismatch\n");
        goto fail;
    }
    if (nladdr.nl_family != AF_NETLINK) {
        fmt::print(stderr, "get_tcp_uid: getsockname address type mismatch\n");
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
bool Netlink::get_if_stats(std::vector<IfStats> &ifs)
{
    bool ret(false);
    if (!open(NETLINK_ROUTE)) {
        fmt::print(stderr, "failed to create netlink socket\n");
        return ret;
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
        fmt::print(stderr, "get_if_stats: recv() error: {}\n", strerror(errno));
        return ret;
    }

  again:
    for (nlh = reinterpret_cast<struct nlmsghdr *>(buf);
         nlmsg_ok(nlh, rbytes); nlh = nlmsg_next(nlh, rbytes)) {
        if (nlh->nlmsg_pid != portid_) {
            fmt::print(stderr, "get_if_stats: bad portid: {} != {}\n",
                       nlh->nlmsg_pid, portid_);
            continue;
        }
        if (nlh->nlmsg_seq != this_seq) {
            fmt::print(stderr, "get_if_stats: bad seq: {} != {}\n",
                       nlh->nlmsg_seq, this_seq);
            continue;
        }

        if (nlh->nlmsg_type == NLMSG_DONE) {
            ret = true;
            break;
        }
        if (nlh->nlmsg_type == NLMSG_ERROR) {
            fmt::print(stderr, "get_if_stats: received NLMSG_ERROR reply\n");
            break;
        }

        if (nlh->nlmsg_type == RTM_NEWLINK) {
            const struct ifinfomsg * const ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
            const struct rtattr *tb[IFLA_MAX+1] = {};

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
            const auto name((const char * const)RTA_DATA(tb[IFLA_IFNAME]));
            for (auto &i: ifs) {
                if (i.name == name) {
                    // idx: 0 = rxpkts, 1 = txpkts, 2 = rxbytes, 3 = txbytes
                    uint32_t ival[NLK_RTM_NL_DATAMAX] = {};
                    memcpy(ival, RTA_DATA(tb[IFLA_STATS]), sizeof ival);
                    i.rx = ival[2];
                    i.tx = ival[3];
                    break;
                }
            }
        }
    }
    if ((rbytes = recv(fd_, buf, sizeof buf, MSG_DONTWAIT)) >= 0)
        goto again;
    return ret;
}

// v6 -> v4 is VALID IIF v6ismapped|v6iscompat
static bool ip_addr_eq(const asio::ip::address &a, const asio::ip::address_v4 &v, bool src)
{
    if (a.is_v4()) {
        if (a != v) {
            fmt::print(stderr, "v4_addreq: {} addresses do not match - a/v4 [{}] != v/v4 [{}]\n",
                       src?"src":"dst", a, v);
            return false;
        }
        return true;
    }

    auto a6 = a.to_v6();
    bool a6mapped(a6.is_v4_mapped()), a6compat(a6.is_v4_compatible());
    if (a6mapped || a6compat) {
        asio::ip::address_v4 a4;
        try {
            a4 = a6.to_v4();
        } catch (const std::bad_cast &) { goto fail; }
        if (a4 == v)
            return true;
        fmt::print(stderr, "v4_addreq: {} addresses do not match - a/v6{} [{}] != v/v4 [{}]\n",
                   src?"src":"dst", a6mapped?"m":"c", a, v);
        return false;
    }
fail:
    fmt::print(stderr, "v4_addreq: {} addresses do not match - a/v6 [{}] != v/v4 [{}]\n",
               src?"src":"dst", a, v);
    return false;
}

static bool ip_addr_eq(const asio::ip::address &a, const asio::ip::address_v6 &v, bool src)
{
    if (a.is_v6()) {
        auto a6 = a.to_v6();
        bool amapped(a6.is_v4_mapped()), acompat(a6.is_v4_compatible());
        if (amapped || acompat) {
            asio::ip::address_v4 a4;
            try {
                a4 = a6.to_v4();
            } catch (const std::bad_cast &) { goto normal_test; }
            bool vmapped(v.is_v4_mapped()), vcompat(v.is_v4_compatible());
            if (vmapped || vcompat) {
                asio::ip::address_v4 v4;
                try {
                    v4 = v.to_v4();
                } catch (const std::bad_cast &) { goto fail2; }
                if (a4 == v4)
                    return true;
                fmt::print(stderr, "v6_addreq: {} addresses do not match - a/v4{} [{}] != v/v4{} [{}]\n",
                           src?"src":"dst", amapped?"m":"c", a, vmapped?"m":"c", v);
                return false;
            }
fail2:
            fmt::print(stderr, "v6_addreq: {} addresses do not match - a/v4{} [{}] != v/v4 [{}]\n",
                       src?"src":"dst", amapped?"m":"c", a, v);
            return false;
        }
normal_test:
        if (a != v) {
            fmt::print(stderr, "v6_addreq: {}"" addresses do not match - a/v6 [{}] != v/v6 [{}]\n",
                       src?"src":"dst", a, v);
            return false;
        }
        return true;
    }
    bool vmapped(v.is_v4_mapped()), vcompat(v.is_v4_compatible());
    if (vmapped || vcompat) {
        asio::ip::address_v4 v4;
        try {
            v4 = v.to_v4();
        } catch (const std::bad_cast &) { goto fail; }
        if (a == v4)
            return true;
        fmt::print(stderr, "v6_addreq: {} addresses do not match - a/v4 [{}] != v/v6{} [{}]\n",
                   src?"src":"dst", a, vmapped?"m":"c", v);
        return false;
    }
fail:
    fmt::print(stderr, "v6_addreq: {} addresses do not match - a/v4 [{}] != v/v6 [{}]\n",
               src?"src":"dst", a, v);
    return false;
}

static inline bool ip_addr_eq(const asio::ip::address &a, const asio::ip::address
                              &v, bool src)
{
    return v.is_v6() ? ip_addr_eq(a, v.to_v6(), src)
                     : ip_addr_eq(a, v.to_v4(), src);
}

int Netlink::get_tcp_uid(asio::ip::address sa, unsigned short sp,
                         asio::ip::address da, unsigned short dp)
{
    int uid = -1;

    if (!open(NETLINK_INET_DIAG)) {
        fmt::print(stderr, "failed to create netlink socket\n");
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
    char bcbuf[2 * (sizeof(struct inet_diag_bc_op)
                    + sizeof(struct inet_diag_hostcond) + 16)];
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
        fmt::print(stderr, "get_tcp_uid: sendmsg() error: {}\n",
                   strerror(errno));
        return uid;
    }

    char buf[8192];
    iov[0].iov_base = buf;
    iov[0].iov_len = sizeof buf;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    int rbytes = recvmsg(fd_, &msg, MSG_WAITALL);
    if (rbytes < 0) {
        fmt::print(stderr, "get_tcp_uid: recvmsg() error: {}\n",
                   strerror(errno));
        return uid;
    }

  again:
    for (nlh = reinterpret_cast<struct nlmsghdr *>(buf);
         nlmsg_ok(nlh, rbytes); nlh = nlmsg_next(nlh, rbytes)) {
        if (nlh->nlmsg_pid != portid_) {
            fmt::print(stderr, "get_tcp_uid: bad portid: {} != {}\n",
                       nlh->nlmsg_pid, portid_);
            continue;
        }
        if (nlh->nlmsg_seq != this_seq) {
            fmt::print(stderr, "get_tcp_uid: bad seq: {} != {}\n",
                       nlh->nlmsg_seq, this_seq);
            continue;
        }

        if (nlh->nlmsg_type == NLMSG_DONE)
            break;
        if (nlh->nlmsg_type == NLMSG_ERROR) {
            fmt::print(stderr, "get_tcp_uid: received NLMSG_ERROR reply\n");
            break;
        }

        if (nlh->nlmsg_type == TCPDIAG_GETSOCK) {
            struct inet_diag_msg *r = (struct inet_diag_msg *)NLMSG_DATA(nlh);

            unsigned short sport = ntohs(r->id.idiag_sport);
            unsigned short dport = ntohs(r->id.idiag_dport);
            if (sport != sp || dport != dp) {
                fmt::print(stderr, "get_tcp_uid: ports (sp,dp)=({},{}) != ({},{})\n",
                           sp, dp, sport, dport);
                continue;
            }

            if (r->idiag_family == AF_INET6) {
                asio::ip::address_v6::bytes_type s6b, d6b;
                memcpy(s6b.data(), r->id.idiag_src, 16);
                memcpy(d6b.data(), r->id.idiag_dst, 16);
                auto rs = asio::ip::address_v6(s6b);
                auto rd = asio::ip::address_v6(d6b);
                if (!ip_addr_eq(sa, rs, true))
                    continue;
                if (!ip_addr_eq(da, rd, false))
                    continue;
            } else {
                asio::ip::address_v4::bytes_type s4b, d4b;
                memcpy(s4b.data(), r->id.idiag_src, 4);
                memcpy(d4b.data(), r->id.idiag_dst, 4);
                auto rs = asio::ip::address_v4(s4b);
                auto rd = asio::ip::address_v4(d4b);
                if (!ip_addr_eq(sa, rs, true))
                    continue;
                if (!ip_addr_eq(da, rd, false))
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
