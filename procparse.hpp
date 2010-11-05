#ifndef PROCPARSE_H_
#define PROCPARSE_H_

#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#include <arpa/inet.h>

class ProcParse {
public:
    enum HostType {
        HostNone,
        HostName,
        HostIP4,
        HostIP6
    };
    enum PolicyAction {
        PolicyNone,
        PolicyAccept,
        PolicyDeny,
        PolicySpoof,
        PolicyHash
    };
    struct Policy {
        enum HashItem {
            fHashNone = 0,
            fHashUID = 1,
            fHashIP = 2,
            fHashSP = 4,
            fHashDP = 8
        };
        PolicyAction action;
        std::string spoof;
        Policy() { action = PolicyNone; hashitems = fHashNone; }
        void setHashUID() { hashitems |= fHashUID; }
        void setHashIP() { hashitems |= fHashIP; }
        void setHashSP() { hashitems |= fHashSP; }
        void setHashDP() { hashitems |= fHashDP; }
        bool isHashUID() const { return (hashitems & fHashUID) ? true : false; }
        bool isHashIP() const { return (hashitems & fHashIP) ? true : false; }
        bool isHashSP() const { return (hashitems & fHashSP) ? true : false; }
        bool isHashDP() const { return (hashitems & fHashDP) ? true : false; }
    private:
        int hashitems;
    };
    struct ConfigItem {
        HostType type;
        struct in6_addr host;
        int mask;
        int low_lport;
        int high_lport;
        int low_rport;
        int high_rport;
        Policy policy;
        ConfigItem() {
            type = HostNone; mask = -1;
            low_lport = -1; high_lport = -1;
            low_rport = -1; high_rport = -1;
        }
    };
    struct ProcTcpItem {
        struct in6_addr local_address_; // check with getsockname
        unsigned short local_port_;
        struct in6_addr remote_address_; // check with getpeername
        unsigned short remote_port_;
        int uid;
    };
    void parse_tcp(const std::string &fn);
    void parse_tcp6(const std::string &fn);
    void parse_cfg(const std::string &fn);
    bool compare_ipv6(struct in6_addr ip, struct in6_addr mask, int msize);
    struct in6_addr canon_ipv6(const std::string &ip, bool *ok = NULL);
    std::vector<ProcTcpItem> tcp_items;
    std::vector<ConfigItem> cfg_items;
};

#endif /* PROCPARSE_H_ */
