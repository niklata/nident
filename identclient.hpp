#ifndef NK_IDENTCLIENT_H
#define NK_IDENTCLIENT_H

#include <string>

class IdentClient {
public:
    enum IdentClientState {
        STATE_WAITIN,
        STATE_GOTIN,
        STATE_WAITOUT,
        STATE_DONE
    };

    const int fd_;
    std::string inbuf_;
    std::string outbuf_;
    IdentClientState state_;

    int server_port_; // Port on the local machine this server is running on.
    int client_port_; // Port on the remote machine making the ident request.
    std::string response_;
    std::string add_info_;

    IdentClient(int fd);
    ~IdentClient();

    bool process_input();
    bool parse_request();
    bool create_reply();
    bool process_output();
};

extern unsigned int max_client_bytes;

#endif /* NK_IDENTCLIENT_H */
