#include "procparse.hpp"

#include <sstream>
#include <boost/regex.hpp>

void ProcParse::parse_tcp(std::string fn)
{
    std::string l;
    std::ifstream f(fn, std::ifstream::in);
    boost::regex re;
    boost::cmatch m;

    if (f.fail() || f.bad() || f.eof()) {
        std::cerr << "failed to open file: '" << fn << "'";
        return;
    }

    // skip the header
    std::getline(f, l);
    if (f.eof()) {
        std::cerr << "no tcp connections\n";
        f.close();
        return;
    } else if (f.bad()) {
        std::cerr << "fatal io error getting first line of proc/net/tcp\n";
        f.close();
        return;
    } else if (f.fail()) {
        std::cerr << "non-fatal io error getting first line of proc/net/tcp\n";
        f.close();
        return;
    }

    // sl local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid
    // 0: 00000000:2383 00000000:0000 0A 00000000:00000000 00:00000000 00000000   109
    re.assign("\\s*\\d+:" // sl
              "\\s+([0-9a-fA-F]{2})([0-9a-fA-F]{2})([0-9a-fA-F]{2})([0-9a-fA-F]{2}):([0-9a-fA-F]{2})([0-9a-fA-F]{2})" // local
              "\\s+([0-9a-fA-F]{2})([0-9a-fA-F]{2})([0-9a-fA-F]{2})([0-9a-fA-F]{2}):([0-9a-fA-F]{2})([0-9a-fA-F]{2})" // remote
              "\\s+[0-9a-fA-F]{2}" // st
              "\\s+[0-9a-fA-F]{8}:[0-9a-fA-F]{8}" // tx_queue:rx_queue
              "\\s+[0-9a-fA-F]{2}:[0-9a-fA-F]{8}" // tr:tm->when
              "\\s+[0-9a-fA-F]{8}" // retrnsmt
              "\\s+(\\d+)" // uid
              "\\s+\\d+.*" // timeout
              , boost::regex_constants::icase);

    while (1) {
        std::getline(f, l);
        if (f.eof()) {
            std::cerr << "end of tcp connections\n";
            break;
        } else if (f.bad()) {
            std::cerr << "fatal io error fetching line of proc/net/tcp\n";
            break;
        } else if (f.fail()) {
            std::cerr << "non-fatal io error fetching line of proc/net/tcp\n";
            break;
        }

        if (boost::regex_match(l.c_str(), m, re)) {
            std::stringstream as, bs, cs, ds, es, fs, gs, hs, ls, rs;
            unsigned int a, b, c, d, e, f, g, h, lp, rp;
            as << std::hex << m[4];
            as >> a;
            bs << std::hex << m[3];
            bs >> b;
            cs << std::hex << m[2];
            cs >> c;
            ds << std::hex << m[1];
            ds >> d;
            std::cout << "locl4: " << a << "." << b << "." << c << "." << d << "\n";
            std::cout << "locl6: " << "0000:0000:0000:0000:0000:ffff:"
                      << m[4] << m[3] << ":" << m[2] << m[1] << "\n";
            ls << std::hex << m[6] << m[5];
            ls >> lp;
            std::cout << "lport: " << lp << "\n";
            es << std::hex << m[10];
            es >> e;
            fs << std::hex << m[9];
            fs >> f;
            gs << std::hex << m[8];
            gs >> g;
            hs << std::hex << m[7];
            hs >> h;
            std::cout << "rmot4: " << e << "." << f << "." << g << "." << h << "\n";
            std::cout << "rmot6: " << "0000:0000:0000:0000:0000:ffff:"
                      << m[10] << m[9] << ":" << m[8] << m[7] << "\n";
            rs << std::hex << m[12] << m[11];
            rs >> rp;
            std::cout << "rport: " << rp << "\n";
            std::cout << "uid: " << m[13] << "\n";
        }
    }
    f.close();
}

void ProcParse::parse_tcp6(std::string fn)
{
    std::string l;
    std::ifstream f(fn, std::ifstream::in);
    boost::regex re;
    boost::cmatch m;

    if (f.fail() || f.bad() || f.eof()) {
        std::cerr << "failed to open file: '" << fn << "'";
        return;
    }

    // skip the header
    std::getline(f, l);
    if (f.eof()) {
        std::cerr << "no tcp connections\n";
        f.close();
        return;
    } else if (f.bad()) {
        std::cerr << "fatal io error getting first line of proc/net/tcp\n";
        f.close();
        return;
    } else if (f.fail()) {
        std::cerr << "non-fatal io error getting first line of proc/net/tcp\n";
        f.close();
        return;
    }

    // sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
    // 12: 700401200000B4E20000000001000000:D063 28F1072601054000EFBEADDECCCCFECA:1A29 01 00000000:00000000 02:00053FAD 00000000  1000        0 4039830 2 ffff
    re.assign("\\s*\\d+:\\s+" // sl
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              ":([0-9a-fA-F]{2})([0-9a-fA-F]{2})" // local
              "\\s+"
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              "([0-9a-fA-F]{2})([0-9a-fA-F]{2})"
              ":([0-9a-fA-F]{2})([0-9a-fA-F]{2})" // remote
              "\\s+[0-9a-fA-F]{2}" // st
              "\\s+[0-9a-fA-F]{8}:[0-9a-fA-F]{8}" // tx_queue:rx_queue
              "\\s+[0-9a-fA-F]{2}:[0-9a-fA-F]{8}" // tr:tm->when
              "\\s+[0-9a-fA-F]{8}" // retrnsmt
              "\\s+(\\d+)" // uid
              "\\s+\\d+.*" // timeout
              , boost::regex_constants::icase);

    while (1) {
        std::getline(f, l);
        if (f.eof()) {
            std::cerr << "end of tcp connections\n";
            break;
        } else if (f.bad()) {
            std::cerr << "fatal io error fetching line of proc/net/tcp\n";
            break;
        } else if (f.fail()) {
            std::cerr << "non-fatal io error fetching line of proc/net/tcp\n";
            break;
        }

        if (boost::regex_match(l.c_str(), m, re)) {
            std::stringstream ls, rs;
            unsigned int lp, rp;
            std::cout << "local: " << m[4] << m[3] << ":" << m[2] << m[1] << ":"
                      << m[8] << m[7] << ":" << m[6] << m[5] << ":"
                      << m[12] << m[11] << ":" << m[10] << m[9] << ":"
                      << m[16] << m[15] << ":" << m[14] << m[13] << "\n";
            ls << std::hex << m[18] << m[17];
            ls >> lp;
            std::cout << "lport: " << lp << "\n";
            std::cout << "rmote: " << m[22] << m[21] << ":" << m[20] << m[19] << ":"
                      << m[26] << m[25] << ":" << m[24] << m[23] << ":"
                      << m[30] << m[29] << ":" << m[28] << m[27] << ":"
                      << m[34] << m[33] << ":" << m[32] << m[31] << "\n";
            rs << std::hex << m[36] << m[35];
            rs >> rp;
            std::cout << "rport: " << rp << "\n";
            std::cout << "uid: " << m[37] << "\n";
        }
    }
    f.close();
}
