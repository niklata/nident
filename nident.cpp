/* nident.c - ident server
 * Time-stamp: <2012-07-16 12:52:10 nk>
 *
 * (c) 2004-2012 Nicholas J. Kain <njkain at gmail dot com>
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

#define NIDENT_VERSION "1.0"

#include <memory>
#include <string>
#include <vector>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

#include <pwd.h>
#include <grp.h>

#include <signal.h>
#include <errno.h>
#include <getopt.h>

#include <boost/asio.hpp>
#include <boost/program_options.hpp>

#include "identclient.hpp"
#include "netlink.hpp"

extern "C" {
#include "defines.h"
#include "malloc.h"
#include "log.h"
#include "chroot.h"
#include "pidfile.h"
#include "strl.h"
#include "exec.h"
#include "network.h"
#include "strlist.h"
}

namespace po = boost::program_options;

boost::asio::io_service io_service;
std::unique_ptr<Netlink> nlink;
bool gParanoid = false;
bool gChrooted = false;

static void sighandler(int sig)
{
    exit(EXIT_SUCCESS);
}

static void fix_signals(void) {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGPIPE);
    sigaddset(&mask, SIGUSR1);
    sigaddset(&mask, SIGUSR2);
    sigaddset(&mask, SIGTSTP);
    sigaddset(&mask, SIGTTIN);
    sigaddset(&mask, SIGHUP);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0)
	suicide("sigprocmask failed");

    struct sigaction sa;
    memset(&sa, 0, sizeof (struct sigaction));
    sa.sa_handler = sighandler;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGINT);
    sigaddset(&sa.sa_mask, SIGTERM);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

int main(int ac, char *av[]) {
    int uid = 0, gid = 0;
    std::string pidfile, chroot_path;
    std::vector<std::unique_ptr<ClientListener>> listeners;
    std::vector<std::string> addrlist;

    gflags_log_name = const_cast<char *>("nident");

    po::options_description desc("Options");
    desc.add_options()
	("paranoid,p",
	 "return UNKNOWN-ERROR for all errors except INVALID-PORT (prevents inference of used ports)")
        ("detach,d", "run as a background daemon (default)")
        ("nodetach,n", "stay attached to TTY")
        ("quiet,q", "don't print to std(out|err) or log")
        ("pidfile,f", po::value<std::string>(),
         "path to process id file")
        ("chroot,c", po::value<std::string>(),
         "path in which nident should chroot itself")
	("max-bytes,b", po::value<int>(),
	 "maximum number of bytes allowed from a client")
	("address,a", po::value<std::vector<std::string> >(),
	 "'address[:port]' on which to listen (default all local)")
	("user,u", po::value<std::string>(),
	 "user name that nident should run as")
	("group,g", po::value<std::string>(),
	 "group name that nident should run as")
        ("help,h", "print help message")
        ("version,v", "print version information")
        ;
    po::positional_options_description p;
    p.add("address", -1);
    po::variables_map vm;
    try {
        po::store(po::command_line_parser(ac, av).
                  options(desc).positional(p).run(), vm);
    } catch(std::exception& e) {
        std::cerr << e.what() << std::endl;
    }
    po::notify(vm);

    if (vm.count("help")) {
        std::cout << "nident " << NIDENT_VERSION << ", ident server.\n"
		  << "Copyright (c) 2010-2012 Nicholas J. Kain\n"
		  << av[0] << " [options] addresses...\n"
		  << desc << std::endl;
        return 1;
    }
    if (vm.count("version")) {
	std::cout << "nident " << NIDENT_VERSION << ", ident server.\n" <<
	    "Copyright (c) 2010-2012 Nicholas J. Kain\n"
	    "All rights reserved.\n\n"
	    "Redistribution and use in source and binary forms, with or without\n"
	    "modification, are permitted provided that the following conditions are met:\n\n"
	    "- Redistributions of source code must retain the above copyright notice,\n"
	    "  this list of conditions and the following disclaimer.\n"
	    "- Redistributions in binary form must reproduce the above copyright notice,\n"
	    "  this list of conditions and the following disclaimer in the documentation\n"
	    "  and/or other materials provided with the distribution.\n\n"
	    "THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS \"AS IS\"\n"
	    "AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE\n"
	    "IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE\n"
	    "ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE\n"
	    "LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR\n"
	    "CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF\n"
	    "SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS\n"
	    "INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN\n"
	    "CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)\n"
	    "ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE\n"
	    "POSSIBILITY OF SUCH DAMAGE.\n";
        return 1;
    }
    if (vm.count("paranoid"))
	gParanoid = true;
    if (vm.count("detach"))
	gflags_detach = 1;
    if (vm.count("nodetach"))
	gflags_detach = 0;
    if (vm.count("quiet"))
	gflags_quiet = 1;
    if (vm.count("max-bytes")) {
	max_client_bytes = vm["max-bytes"].as<int>();
	if (max_client_bytes < 64)
	    max_client_bytes = 64;
	else if (max_client_bytes > 1024)
	    max_client_bytes = 1024;
    }
    if (vm.count("pidfile"))
	pidfile = vm["pidfile"].as<std::string>();
    if (vm.count("chroot"))
	chroot_path = vm["chroot"].as<std::string>();
    if (vm.count("address"))
	addrlist = vm["address"].as<std::vector<std::string> >();
    if (vm.count("user")) {
	auto t = vm["user"].as<std::string>();
	try {
	    uid = boost::lexical_cast<unsigned int>(t);
	} catch (boost::bad_lexical_cast &) {
	    auto pws = getpwnam(t.c_str());
	    if (pws) {
		uid = (int)pws->pw_uid;
		if (!gid)
		    gid = (int)pws->pw_gid;
	    } else suicide("invalid uid specified");
	}
    }
    if (vm.count("group")) {
	auto t = vm["group"].as<std::string>();
	try {
	    gid = boost::lexical_cast<unsigned int>(t);
	} catch (boost::bad_lexical_cast &) {
	    auto grp = getgrnam(t.c_str());
	    if (grp) {
		gid = (int)grp->gr_gid;
	    } else suicide("invalid gid specified");
	}
    }

    if (gflags_detach)
	if (daemon(0,0))
	    suicide("detaching fork failed");

    if (pidfile.size() && file_exists(pidfile.c_str(), "w"))
	write_pid(pidfile.c_str());

    umask(077);
    fix_signals();
    ncm_fix_env(uid, 0);

    if (!addrlist.size()) {
	auto ep = boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v6(), 113);
	listeners.emplace_back(std::unique_ptr<ClientListener>(
				   new ClientListener(ep)));
    } else
	for (auto i = addrlist.cbegin(); i != addrlist.cend(); ++i) {
	    std::string addr = *i;
	    int port = 113;
	    auto loc = addr.rfind(":");
	    if (loc != std::string::npos) {
		auto pstr = addr.substr(loc + 1);
		try {
		    port = boost::lexical_cast<unsigned short>(pstr);
		} catch (boost::bad_lexical_cast &) {
		    std::cout << "bad port in address '" << addr
			      << "', defaulting to 113" << std::endl;
		}
		addr.erase(loc);
	    }
	    try {
		auto addy = boost::asio::ip::address::from_string(addr);
		auto ep = boost::asio::ip::tcp::endpoint(addy, port);
		listeners.emplace_back(std::unique_ptr<ClientListener>(
					    new ClientListener(ep)));
	    } catch (boost::system::error_code &ec) {
		std::cout << "bad address: " << addr << std::endl;
	    }
	}
    addrlist.clear();

    nlink = std::unique_ptr<Netlink>(new Netlink);
    if (!nlink->open(NETLINK_INET_DIAG)) {
	std::cerr << "failed to create netlink socket" << std::endl;
	exit(EXIT_FAILURE);
    }

    if (chroot_path.size()) {
	if (getuid())
	    suicide("root required for chroot\n");
	if (chdir(chroot_path.c_str()))
	    suicide("failed to chdir(%s)\n", chroot_path.c_str());
	if (chroot(chroot_path.c_str()))
	    suicide("failed to chroot(%s)\n", chroot_path.c_str());
	gChrooted = true;
	chroot_path.clear();
    }
    if (uid != 0 || gid != 0)
	drop_root(uid, gid);

    /* Cover our tracks... */
    pidfile.clear();

    io_service.run();

    exit(EXIT_SUCCESS);
}

