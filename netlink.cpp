#include <iostream>
#include <unistd.h>
#include "netlink.hpp"
namespace ba = boost::asio;

int Netlink::bc_size(int salen, int calen)
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

int Netlink::get_tcp_uid(ba::ip::address sa, unsigned short sp,
                         ba::ip::address da, unsigned short dp)
{
    int uid = -1;
    int salen = sa.is_v4() ? 4 : 16;
    int dalen = da.is_v4() ? 4 : 16;
    int bclen = bc_size(salen, dalen);

    if (sa.is_v6() != da.is_v6()) {
        std::cerr << "saddr and daddr must both be IPv4 or both be IPv6"
                  << std::endl;
        return uid;
    }

    int fdt = socket(AF_NETLINK, SOCK_RAW, NETLINK_INET_DIAG);
    if (fdt < 0) {
        std::cerr << "get_tcp_uid: socket() error: " << strerror(errno)
                  << std::endl;
        return uid;
    }
    NetlinkFd fd(fdt);

    struct sockaddr_nl nladdr;
    memset(&nladdr, 0, sizeof nladdr);
    nladdr.nl_family = AF_NETLINK;

    if (bind(fd.data(), (struct sockaddr *)&nladdr, sizeof nladdr) < 0) {
        std::cerr << "get_tcp_uid: bind() error: " << strerror(errno)
                  << std::endl;
        return uid;
    }
    socklen_t nladdr_len = sizeof nladdr;
    if (getsockname(fd.data(), (struct sockaddr *)&nladdr, &nladdr_len) < 0) {
        std::cerr << "get_tcp_uid: getsockname() error: " << strerror(errno)
                  << std::endl;
        return uid;
    }
    if (nladdr_len != sizeof nladdr) {
        std::cerr << "get_tcp_uid: getsockname address length mismatch"
                  << std::endl;
        return uid;
    }
    if (nladdr.nl_family != AF_NETLINK) {
        std::cerr << "get_tcp_uid: getsockname address type mismatch"
                  << std::endl;
        return uid;
    }

    unsigned int portid = nladdr.nl_pid;
    unsigned int seq;

    struct nlmsghdr *nlh;
    struct {
        struct nlmsghdr nlh;
        struct inet_diag_req r;
    } req;
    struct iovec iov[3];
    struct msghdr msg;
    struct rtattr rta;

    memset(&nladdr, 0, sizeof nladdr);
    nladdr.nl_family = AF_NETLINK;

    req.nlh.nlmsg_len = sizeof req;
    req.nlh.nlmsg_type = TCPDIAG_GETSOCK;
    req.nlh.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
    req.nlh.nlmsg_pid = portid;
    req.nlh.nlmsg_seq = seq = time(NULL);
    memset(&req.r, 0, sizeof req.r);
    req.r.idiag_family = AF_INET;
    req.r.idiag_states = TCPF_ESTABLISHED;
    req.r.idiag_ext = (1 << (INET_DIAG_INFO-1));

    iov[0].iov_base = &req;
    iov[0].iov_len = sizeof req;
    char *bcbuf = new char[bclen];
    memset(bcbuf, 0, bclen);
    if (salen == 4) {
        create_bc(bcbuf, sa.to_v4().to_bytes().data(), salen, sp,
                  da.to_v4().to_bytes().data(), dalen, dp);
    } else {
        create_bc(bcbuf, sa.to_v6().to_bytes().data(), salen, sp,
                  da.to_v6().to_bytes().data(), dalen, dp);
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

    if (sendmsg(fd.data(), &msg, 0) < 0) {
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

    int rbytes = recvmsg(fd.data(), &msg, 0);
    if (rbytes < 0) {
        std::cerr << "get_tcp_uid: recvmsg() error: " << strerror(errno)
                  << std::endl;
        delete[] bcbuf;
        return uid;
    }

    nlh = reinterpret_cast<struct nlmsghdr *>(buf);

    if (rbytes >= (int)sizeof(struct nlmsghdr) &&
        nlh->nlmsg_len >= sizeof(struct nlmsghdr) &&
        (int)nlh->nlmsg_len <= rbytes) {
        if (nlh->nlmsg_pid != portid) {
            std::cerr << "get_tcp_uid: bad portid: "
                      << nlh->nlmsg_pid << "!=" << portid << std::endl;
            return uid;
        }
        if (nlh->nlmsg_seq != seq) {
            std::cerr << "get_tcp_uid: bad seq: " << seq << std::endl;
            return uid;
        }

        if (nlh->nlmsg_type == TCPDIAG_GETSOCK) {
            struct inet_diag_msg *r = (struct inet_diag_msg *)NLMSG_DATA(nlh);

            unsigned short sport = ntohs(r->id.idiag_sport);
            unsigned short dport = ntohs(r->id.idiag_dport);
            if (sport != sp || dport != dp) {
                std::cerr << "get_tcp_uid: ports do not match " << std::endl;
                return uid;
            }

            ba::ip::address saddr, daddr;
            if (r->idiag_family == AF_INET) {
                ba::ip::address_v4::bytes_type s4b, d4b;
                memcpy(s4b.data(), r->id.idiag_src, 4);
                memcpy(d4b.data(), r->id.idiag_dst, 4);
                saddr = ba::ip::address(ba::ip::address_v4(s4b));
                daddr = ba::ip::address(ba::ip::address_v4(d4b));
            } else {
                ba::ip::address_v6::bytes_type s6b, d6b;
                memcpy(s6b.data(), r->id.idiag_src, 16);
                memcpy(d6b.data(), r->id.idiag_dst, 16);
                saddr = ba::ip::address(ba::ip::address_v6(s6b));
                daddr = ba::ip::address(ba::ip::address_v6(s6b));
            }
            if (saddr != sa || daddr != da) {
                std::cerr << "get_tcp_uid: addresses do not match " << std::endl;
                return uid;
            }

            uid = r->idiag_uid;
            // std::cout << "src: " << saddr << ":" << sport << std::endl;
            // std::cout << "dst: " << daddr << ":" << dport << std::endl;
        }
    }
    return uid;
}
