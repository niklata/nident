#include <iostream>

#include <unistd.h>
#include <arpa/inet.h>

#include <linux/inet_diag.h>
#include <linux/rtnetlink.h>

#include <boost/asio.hpp>
namespace ba = boost::asio;
#include <boost/program_options.hpp>
namespace po = boost::program_options;

enum {
    TCPF_ESTABLISHED = (1 << 1),
    TCPF_SYN_SENT    = (1 << 2),
    TCPF_SYN_RECV    = (1 << 3),
    TCPF_FIN_WAIT1   = (1 << 4),
    TCPF_FIN_WAIT2   = (1 << 5),
    TCPF_TIME_WAIT   = (1 << 6),
    TCPF_CLOSE       = (1 << 7),
    TCPF_CLOSE_WAIT  = (1 << 8),
    TCPF_LAST_ACK    = (1 << 9),
    TCPF_LISTEN      = (1 << 10),
    TCPF_CLOSING     = (1 << 11)
};

int bc_size(int salen, int calen)
{
    return 12 + 2 * sizeof (struct inet_diag_hostcond) + salen + calen;
}

// Returns the length of the message stored in bcbase or 0 on failure.
int create_bc(char *bcbase, unsigned char *sabytes, int salen, uint16_t sport,
              unsigned char *cabytes, int calen, uint16_t dport)
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

int main(int argc, const char *argv[])
{
    std::string sastr, dastr;
    unsigned short sp, dp;

    po::options_description desc("Allowed options");
    desc.add_options()
        ("sa", po::value<std::string>(),
         "source address that will be checked in printable format")
        ("sp", po::value<unsigned short>(),
         "source port that will be checked")
        ("da", po::value<std::string>(),
         "destination address that will be checked in printable format")
        ("dp", po::value<unsigned short>(),
         "destination port that will be checked")
        ;
    po::positional_options_description p;
    p.add("sa", 1).add("sp", 1).add("da", 1).add("dp", 1);
    po::variables_map vm;
    try {
        po::store(po::command_line_parser(argc, argv).
                  options(desc).positional(p).run(), vm);
    } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
    }
    po::notify(vm);

    if (vm.count("sa"))
        sastr = vm["sa"].as<std::string>();
    if (vm.count("sp"))
        sp = vm["sp"].as<unsigned short>();
    if (vm.count("da"))
        dastr = vm["da"].as<std::string>();
    if (vm.count("dp"))
        dp = vm["dp"].as<unsigned short>();

    if (!sastr.size()) {
        std::cerr << "no source address specified\n";
        exit(-1);
    }
    if (!sp) {
        std::cerr << "no source port specified\n";
        exit(-1);
    }
    if (!dastr.size()) {
        std::cerr << "no destination address specified\n";
        exit(-1);
    }
    if (!dp) {
        std::cerr << "no destination port specified\n";
        exit(-1);
    }

    std::cout << "src: " << sastr << ":" << sp << " dst: " << dastr << ":" << dp
              << std::endl;

    namespace ba = boost::asio;
    ba::ip::address sa = ba::ip::address::from_string(sastr);
    ba::ip::address da = ba::ip::address::from_string(dastr);
    int salen, dalen;

    if (sa.is_v6() != da.is_v6()) {
        std::cerr << "src and dst must both be IPv4 or both be IPv6"
                  << std::endl;
        exit(-1);
    }

    if (sa.is_v4())
        salen = 4;
    else
        salen = 16;
    if (da.is_v4())
        dalen = 4;
    else
        dalen = 16;
    int bclen = bc_size(salen, dalen);

    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_INET_DIAG);
    if (fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_nl nladdr;
    memset(&nladdr, 0, sizeof nladdr);
    nladdr.nl_family = AF_NETLINK;

    if (bind(fd, (struct sockaddr *)&nladdr, sizeof nladdr) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }
    socklen_t nladdr_len = sizeof nladdr;
    if (getsockname(fd, (struct sockaddr *)&nladdr, &nladdr_len) < 0) {
        perror("getsockname");
        exit(EXIT_FAILURE);
    }
    if (nladdr_len != sizeof nladdr) {
        std::cerr << "getsockname address length mismatch" << std::endl;
        exit(EXIT_FAILURE);
    }
    if (nladdr.nl_family != AF_NETLINK) {
        std::cerr << "getsockname address type mismatch" << std::endl;
        exit(EXIT_FAILURE);
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

    if (sendmsg(fd, &msg, 0) < 0)
        return -1;

    delete[] bcbuf;

    char buf[getpagesize()];
    iov[0].iov_base = buf;
    iov[0].iov_len = sizeof buf;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    int rbytes = recvmsg(fd, &msg, 0);
    if (rbytes < 0) {
        perror("recvmsg");
        exit(EXIT_FAILURE);
    }

    nlh = reinterpret_cast<struct nlmsghdr *>(buf);

    if (rbytes >= (int)sizeof(struct nlmsghdr) &&
        nlh->nlmsg_len >= sizeof(struct nlmsghdr) &&
        (int)nlh->nlmsg_len <= rbytes) {
        if (nlh->nlmsg_pid != portid) {
            std::cerr << "bad portid: " << nlh->nlmsg_pid << "!=" << portid << std::endl;
            goto badmsg;
        }
        if (nlh->nlmsg_seq != seq) {
            std::cerr << "bad seq: " << seq << std::endl;
            goto badmsg;
        }

        if (nlh->nlmsg_type == TCPDIAG_GETSOCK) {
            struct inet_diag_msg *r = (struct inet_diag_msg *)NLMSG_DATA(nlh);

            unsigned short sport = ntohs(r->id.idiag_sport);
            unsigned short dport = ntohs(r->id.idiag_dport);
            int uid = r->idiag_uid;

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

            std::cout << "src: " << saddr << ":" << sport << std::endl;
            std::cout << "dst: " << daddr << ":" << dport << std::endl;
            std::cout << "uid: " << uid << std::endl;
        }
    }
  badmsg:

    close(fd);

    return 0;
}
