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
    std::cout << "1" << std::endl;
    std::getline(f, l);
    std::cout << "Line: '" << l << "'\n";
    std::cout << "2" << std::endl;
    if (f.eof()) {
        std::cerr << "no tcp connections\n";
        goto out;
    } else if (f.bad()) {
        std::cerr << "fatal io error getting first line of proc/net/tcp\n";
        goto out;
    } else if (f.fail()) {
        std::cerr << "non-fatal io error getting first line of proc/net/tcp\n";
        goto out;
    }

    std::cout << "3" << std::endl;

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

        // sl local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid
        // 0: 00000000:2383 00000000:0000 0A 00000000:00000000 00:00000000 00000000   109
        std::cout << "line: '" << l << "'\n";

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
            std::cout << "local: " << a << "." << b << "." << c << "." << d << "\n";
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
            std::cout << "rmote: " << e << "." << f << "." << g << "." << h << "\n";
            rs << std::hex << m[12] << m[11];
            rs >> rp;
            std::cout << "rport: " << rp << "\n";
            std::cout << "uid: " << m[13] << "\n";
        }
    }
    std::cout << "4" << std::endl;

  out:
    f.close();
}
