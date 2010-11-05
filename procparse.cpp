#include "procparse.hpp"

#include <sstream>
#include <boost/regex.hpp>

#include <string.h>

void ProcParse::parse_tcp(const std::string &fn)
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
              "\\s+\\d+.*"); // timeout

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
            ProcTcpItem ti;
            std::stringstream as, bs, cs, ds, es, fs, gs, hs, ls, rs, us;
            std::stringstream la6, ra6;
            unsigned int a, b, c, d, e, f, g, h;

            as << std::hex << m[4];
            as >> a;
            bs << std::hex << m[3];
            bs >> b;
            cs << std::hex << m[2];
            cs >> c;
            ds << std::hex << m[1];
            ds >> d;
            la6 << "0000:0000:0000:0000:0000:ffff:"
                << a << "." << b << "." << c << "." << d;
            ti.local_address_ = canon_ipv6(la6.str());
            ls << std::hex << m[6] << m[5];
            ls >> ti.local_port_;
            es << std::hex << m[10];
            es >> e;
            fs << std::hex << m[9];
            fs >> f;
            gs << std::hex << m[8];
            gs >> g;
            hs << std::hex << m[7];
            hs >> h;
            ra6 << "0000:0000:0000:0000:0000:ffff:"
                << e << "." << f << "." << g << "." << h;
            ti.remote_address_ = canon_ipv6(ra6.str());
            rs << std::hex << m[12] << m[11];
            rs >> ti.remote_port_;
            us << m[13];
            us >> ti.uid;
            tcp_items.push_back(ti);

            std::cout << "local: " << "0000:0000:0000:0000:0000:ffff:"
                      << a << "." << b << "." << c << "." << d << "\n";
            std::cout << "lport: " << ti.local_port_ << "\n";
            std::cout << "rmote: " << "0000:0000:0000:0000:0000:ffff:"
                      << e << "." << f << "." << g << "." << h << "\n";
            std::cout << "rport: " << ti.remote_port_ << "\n";
            std::cout << "uid: " << m[13] << "\n";
        }
    }
    f.close();
}

void ProcParse::parse_tcp6(const std::string &fn)
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
              "\\s+\\d+.*"); // timeout

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
            ProcTcpItem ti;
            std::stringstream la6, ra6, ls, rs, us;

            la6 << m[4] << m[3] << ":" << m[2] << m[1] << ":"
                << m[8] << m[7] << ":" << m[6] << m[5] << ":"
                << m[12] << m[11] << ":" << m[10] << m[9] << ":"
                << m[16] << m[15] << ":" << m[14] << m[13];
            ti.local_address_ = canon_ipv6(la6.str());
            ls << std::hex << m[18] << m[17];
            ls >> ti.local_port_;
            ra6 << m[22] << m[21] << ":" << m[20] << m[19] << ":"
                << m[26] << m[25] << ":" << m[24] << m[23] << ":"
                << m[30] << m[29] << ":" << m[28] << m[27] << ":"
                << m[34] << m[33] << ":" << m[32] << m[31];
            ti.remote_address_ = canon_ipv6(ra6.str());
            rs << std::hex << m[36] << m[35];
            rs >> ti.remote_port_;
            us << m[37];
            us >> ti.uid;
            tcp_items.push_back(ti);

            std::cout << "local: " << la6.str() << "\n";
            std::cout << "lport: " << ti.local_port_ << "\n";
            std::cout << "rmote: " << ra6.str() << "\n";
            std::cout << "rport: " << ti.remote_port_ << "\n";
            std::cout << "uid: " << ti.uid << "\n";
        }
    }
    f.close();
}

void ProcParse::parse_cfg(const std::string &fn)
{
    std::string l;
    std::ifstream f(fn, std::ifstream::in);
    boost::regex re, re4, re6, rehost;
    boost::regex re_accept, re_deny, re_spoof, re_hash;
    boost::cmatch m;

    if (f.fail() || f.bad() || f.eof()) {
        std::cerr << "failed to open file: '" << fn << "'";
        return;
    }

    // x.x.x.x[/n] (*|l[:h]) (*|l[:h]) -> POLICY
    // x:x:x:x:x:x:x:x[/n] (*|l[:h]) (*|l[:h]) -> POLICY
    // x:x...x[::][/n] (*|l[:h]) (*|l[:h]) -> POLICY
    // POLICY:
    // deny||accept
    // spoof string
    // hash [uid] [ip] [sp] [dp]
    re.assign("\\s*([a-zA-Z0-9:.-]+)"//"\\s*([0-9A-Fa-f:.]+)" // ipv[46]
              "(?:/(\\d{1,2}))?"
              "\\s+(?:\\*|(\\d{1,5})(?::(\\d{1,5}))?)"
              "\\s+(?:\\*|(\\d{1,5})(?::(\\d{1,5}))?)"
              "\\s*->\\s*([a-zA-Z0-9 \\t]+)");
    re4.assign("^((?:25[0-5]|(2[0-4]|1[0-9]|[1-9])?[0-9])\\.(?:25[0-5]|(2[0-4]|1[0-9]|[1-9])?[0-9])\\.(?:25[0-5]|(2[0-4]|1[0-9]|[1-9])?[0-9])\\.(?:25[0-5]|(2[0-4]|1[0-9]|[1-9])?[0-9]))");
    re6.assign("^(((?=(?>.*?::)(?!.*::)))(::)?(([0-9A-F]{1,4})::?){0,5}|((?5):){6})(\\2((?5)(::?|$)){0,2}|((25[0-5]|(2[0-4]|1[0-9]|[1-9])?[0-9])(\\.|$)){4}|(?5):(?5))(?<![^:]:|\\.)\\z",
               boost::regex_constants::icase);
    rehost.assign("(?:\\.?[A-Za-z0-9-]{1,63})+");
    re_deny.assign("^deny\\s*", boost::regex_constants::icase);
    re_accept.assign("^accept\\s*", boost::regex_constants::icase);
    re_spoof.assign("^spoof\\s+([A-Za-z0-9]+)\\s*",
                    boost::regex_constants::icase);
    re_hash.assign("^hash(\\s+(?:uid|ip|sp|dp))+\\s*",
                   boost::regex_constants::icase);

    while (1) {
        std::getline(f, l);
        std::cout << "\n" << l << "\n";
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
            const std::string hoststr = m[1];
            const std::string polstr = m[7];
            boost::cmatch n, o;
            ConfigItem ci;
            std::stringstream mask, llport, hlport, lrport, hrport;

            if (boost::regex_match(hoststr.c_str(), n, re6)) {
                ci.type = HostIP6;
                ci.host = canon_ipv6(hoststr);
            } else if (boost::regex_match(hoststr.c_str(), n, re4)) {
                std::string tmpstr;
                ci.type = HostIP4;
                tmpstr += "::ffff:";
                tmpstr += hoststr;
                ci.host = canon_ipv6(tmpstr);
            } else if (boost::regex_match(hoststr.c_str(), n, rehost)) {
                ci.type = HostName;
                std::cerr << "support for hostnames NYI\n";
                ci.host = canon_ipv6("::1");
            } else
                continue; // invalid
            mask << std::dec << m[2];
            mask >> ci.mask;
            llport << std::dec << m[3];
            llport >> ci.low_lport;
            hlport << std::dec << m[4];
            hlport >> ci.high_lport;
            lrport << std::dec << m[5];
            lrport >> ci.low_rport;
            hrport << std::dec << m[6];
            hrport >> ci.high_rport;
            if (boost::regex_match(polstr.c_str(), o, re_deny)) {
                ci.policy.action = PolicyDeny;
            } else if (boost::regex_match(polstr.c_str(), o, re_accept)) {
                ci.policy.action = PolicyAccept;
            } else if (boost::regex_match(polstr.c_str(), o, re_spoof)) {
                ci.policy.action = PolicySpoof;
                ci.policy.spoof = o[1];
            } else if (boost::regex_match(polstr.c_str(), o, re_hash)) {
                ci.policy.action = PolicyHash;
                if (boost::regex_match(polstr.c_str(), o, boost::regex(".*?uid.*?")))
                    ci.policy.setHashUID();
                if (boost::regex_match(polstr.c_str(), o, boost::regex(".*?ip.*?")))
                    ci.policy.setHashIP();
                if (boost::regex_match(polstr.c_str(), o, boost::regex(".*?sp.*?")))
                    ci.policy.setHashSP();
                if (boost::regex_match(polstr.c_str(), o, boost::regex(".*?dp.*?")))
                    ci.policy.setHashDP();
            } else
                continue; // invalid
            cfg_items.push_back(ci);

            if (ci.type == HostIP6)
                std::cout << "ipv6: " << hoststr << "\n";
            else if (ci.type == HostIP4)
                std::cout << "ipv4: " << hoststr << "\n";
            else if (ci.type == HostName)
                std::cout << "host: " << hoststr << "\n";
            else
                continue; // invalid
            std::cout << "mask size: " << ci.mask << "\n";
            std::cout << "local low port: " << ci.low_lport << "\n";
            std::cout << "local high port: " << ci.high_lport << "\n";
            std::cout << "remote low port: " << ci.low_rport << "\n";
            std::cout << "remote high port: " << ci.high_rport << "\n";
            if (ci.policy.action == PolicyDeny)
                std::cout << "Policy: deny\n";
            else if (ci.policy.action == PolicyAccept)
                std::cout << "Policy: accept\n";
            else if (ci.policy.action == PolicySpoof)
                std::cout << "Policy: spoof [" << ci.policy.spoof << "]\n";
            else if (ci.policy.action == PolicyHash) {
                std::cout << "Policy: hash";
                if (ci.policy.isHashUID())
                    std::cout << " uid";
                if (ci.policy.isHashIP())
                    std::cout << " ip";
                if (ci.policy.isHashSP())
                    std::cout << " sp";
                if (ci.policy.isHashDP())
                    std::cout << " dp";
                std::cout << "\n";
            } else
                continue; // invalid
        }
    }
    std::cout << "end of config\n";
    f.close();
}

// Forms a proper ipv6 address lacking '::' and '.'
struct in6_addr ProcParse::canon_ipv6(const std::string &ip, bool *ok)
{
    struct in6_addr ret;
    int r;

    r = inet_pton(AF_INET6, ip.c_str(), &ret);
    if (r == 0) {
        if (ok)
            *ok = false;
        std::cerr << "canon_ipv6: not in presentation format\n";
    } else if (r < 0) {
        if (ok)
            *ok = false;
        std::cerr << "canon_ipv6: inet_pton() error " << strerror(errno) << "\n";
    }
    if (ok)
        *ok = true;
    return ret;
}

bool ProcParse::compare_ipv6(const std::string &ip, const std::string &mask,
                             int msize)
{
    boost::regex re6;
    boost::cmatch m;
    re6.assign("^(((?=(?>.*?::)(?!.*::)))(::)?(([0-9A-F]{1,4})::?){0,5}|((?5):){6})(\\2((?5)(::?|$)){0,2}|((25[0-5]|(2[0-4]|1[0-9]|[1-9])?[0-9])(\\.|$)){4}|(?5):(?5))(?<![^:]:|\\.)\\z",
               boost::regex_constants::icase);
    if (!boost::regex_match(ip.c_str(), m, re6))
        return false;
    if (!boost::regex_match(mask.c_str(), m, re6))
        return false;

    return false;
}
