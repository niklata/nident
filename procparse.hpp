#ifndef PROCPARSE_H_
#define PROCPARSE_H_

#include <iostream>
#include <fstream>
#include <string>
#include <vector>

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
    enum HashItem {
        HashNone = 0,
        HashUID = 1,
        HashIP = 2,
        HashSP = 4,
        HashDP = 8
    };
    struct Policy {
        PolicyAction action;
        std::string spoof;
        int hashitems;
        Policy() { action = PolicyNone; hashitems = 0; }
    };
    struct ConfigItem {
        HostType type;
        std::string host;
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
        std::string local_address_; // check with getsockname
        unsigned short local_port_;
        std::string remote_address_; // check with getpeername
        unsigned short remote_port_;
        int uid;
    };
    void parse_tcp(std::string fn);
    void parse_tcp6(std::string fn);
    void parse_cfg(std::string fn);
    std::vector<ProcTcpItem> tcp_items;
    std::vector<ConfigItem> cfg_items;
};

#endif /* PROCPARSE_H_ */
