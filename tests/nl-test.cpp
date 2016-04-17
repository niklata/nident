/* nl-test.cpp - netlink abstraction test code
 *
 * (c) 2011-2014 Nicholas J. Kain <njkain at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <nk/format.hpp>
#include <boost/program_options.hpp>
namespace po = boost::program_options;
#include "netlink.hpp"
namespace ba = boost::asio;

int main(int argc, const char *argv[])
{
    std::string sastr, dastr;
    unsigned short sp = 0, dp = 0;

    po::options_description desc("Allowed options");
    desc.add_options()
        ("rates", po::value<std::string>(),
         "interface name where rates will be checked")
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
        fmt::print(stderr, "{}\n", e.what());
    }
    po::notify(vm);

    if (vm.count("rates")) {
        Netlink nl;
        std::vector<Netlink::IfStats> ifs;
        ifs.emplace_back(vm["rates"].as<std::string>());
        if (nl.get_if_stats(ifs)) {
            fmt::print("rx: {} tx: {}\n", ifs[0].rx, ifs[0].tx);
            exit(EXIT_SUCCESS);
        }
        exit(EXIT_FAILURE);
    }

    if (vm.count("sa"))
        sastr = vm["sa"].as<std::string>();
    if (vm.count("sp"))
        sp = vm["sp"].as<unsigned short>();
    if (vm.count("da"))
        dastr = vm["da"].as<std::string>();
    if (vm.count("dp"))
        dp = vm["dp"].as<unsigned short>();

    if (!sastr.size()) {
        fmt::print(stderr, "no source address specified\n");
        return -1;
    }
    if (!sp) {
        fmt::print(stderr, "no source port specified\n");
        return -1;
    }
    if (!dastr.size()) {
        fmt::print(stderr, "no destination address specified\n");
        return -1;
    }
    if (!dp) {
        fmt::print(stderr, "no destination port specified\n");
        return -1;
    }

    fmt::print("src: {}:{} dst: {}:{}\n", sastr, sp, dastr, dp);

    ba::ip::address sa = ba::ip::address::from_string(sastr);
    ba::ip::address da = ba::ip::address::from_string(dastr);

    Netlink nl;
    int uid = nl.get_tcp_uid(sa, sp, da, dp);
    if (uid >= 0) {
        fmt::print("uid: {}\n", uid);
        return 0;
    }
    return -1;
}

