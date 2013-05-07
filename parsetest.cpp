#include <iostream>
#include <boost/program_options.hpp>
namespace po = boost::program_options;
#include <boost/asio.hpp>
namespace ba = boost::asio;
#include "parse.hpp"
#include "netlink.hpp"
#include "siphash.hpp"

bool gParanoid = false;
#define SALTC1 0x3133731337313373
#define SALTC2 0xd3adb33fd3adb33f
uint64_t gSaltK0 = SALTC1, gSaltK1 = SALTC2;
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
        ("salt,s", po::value<std::string>(),
         "string that should be used as salt for hash replies")
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
    if (vm.count("salt")) {
        auto sst = vm["salt"].as<std::string>();
        gSaltK0 = nk::siphash24_hash(SALTC1, SALTC2, sst.c_str(), sst.size());
        gSaltK1 = nk::siphash24_hash(gSaltK0, SALTC1 ^ SALTC2,
                                     sst.c_str(), sst.size());
    }
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

    ba::ip::address sa, da;
    try {
        sa = ba::ip::address::from_string(sastr);
    } catch (const std::exception&) {
        std::cerr << "invalid source ip address\n";
        return -1;
    }
    try {
        da = ba::ip::address::from_string(dastr);
    } catch (const std::exception&) {
        std::cerr << "invalid destination ip address\n";
        return -1;
    }

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
