#ifndef PROCPARSE_H_
#define PROCPARSE_H_

#include <iostream>
#include <fstream>
#include <string>
#include <vector>

class ProcParse {
public:
    struct ProcTcpItem {
        std::string local_address_;
        unsigned short local_port_;
        std::string remote_address_;
        unsigned short remote_port_;
        int uid;
    };
    void parse_tcp(std::string fn);
    std::vector<ProcTcpItem> items;
};

#endif /* PROCPARSE_H_ */
