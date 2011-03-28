#ifndef NK_NETLINK_H_
#define NK_NETLINK_H_

#include <arpa/inet.h>
#include <linux/inet_diag.h>
#include <linux/rtnetlink.h>
#include <boost/asio.hpp>

class Netlink
{
public:
    int get_tcp_uid(boost::asio::ip::address sa, unsigned short sp,
                    boost::asio::ip::address da, unsigned short dp);
private:
    int bc_size(int salen, int calen);
    int create_bc(char *bcbase, unsigned char *sabytes, int salen,
                  uint16_t sport, unsigned char *cabytes, int calen,
                  uint16_t dport);
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
    class NetlinkFd {
    public:
        NetlinkFd(int fd) : fd_(fd) {}
        ~NetlinkFd() { close(fd_); }
        int data() const { return fd_; }
    private:
        int fd_;
    };
};

#endif /* NK_NETLINK_H_ */
