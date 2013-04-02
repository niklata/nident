#include <iostream>
#include <boost/program_options.hpp>
namespace po = boost::program_options;
#include <boost/asio.hpp>
namespace ba = boost::asio;
#include "parse.hpp"
#include "netlink.hpp"

bool gParanoid = false;
int main(int argc, const char *argv[])
{
    std::string sastr, dastr;
    unsigned short sp, dp;
    std::string reply;

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
    } catch (const std::exception& e) {
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

    ba::ip::address sa = ba::ip::address::from_string(sastr);
    ba::ip::address da = ba::ip::address::from_string(dastr);

    Netlink nl;
    int uid = nl.get_tcp_uid(sa, sp, da, dp);
    if (uid >= 0) {
        std::cout << "uid: " << uid << std::endl;
    }

    //"2001:470:e2b4::1 53199 2600:3c01::f03c:91ff:fe96:8625 6697"
    Parse pa;
    if (pa.parse_cfg("/var/lib/ident/" + std::to_string(uid), sa, sp, da, dp))
        reply = pa.get_response(sa, sp, da, dp, uid);
    std::cout << "reply: " << reply << "\n";
    return 0;
}