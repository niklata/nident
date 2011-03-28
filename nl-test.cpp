#include <iostream>
#include <boost/program_options.hpp>
namespace po = boost::program_options;
#include "netlink.hpp"
namespace ba = boost::asio;

int main(int argc, const char *argv[])
{
    std::string sastr, dastr;
    unsigned short sp, dp;

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
    } catch (std::exception &e) {
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
        return 0;
    }
    return -1;
}

