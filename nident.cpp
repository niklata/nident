/* nident.cpp - ident server
 *
 * (c) 2004-2014 Nicholas J. Kain <njkain at gmail dot com>
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

#define NIDENT_VERSION "1.1"

#include <memory>
#include <string>
#include <vector>
#include <fstream>

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
#include "siphash.hpp"
#include "make_unique.hpp"

extern "C" {
#include "nk/log.h"
#include "nk/privilege.h"
#include "nk/pidfile.h"
#include "nk/seccomp-bpf.h"
#include "nk/exec.h"
}

namespace po = boost::program_options;

boost::asio::io_service io_service;
static boost::asio::signal_set asio_signal_set(io_service);
static std::vector<std::unique_ptr<ClientListener>> listeners;
std::unique_ptr<Netlink> nlink;
bool gParanoid = false;
bool gChrooted = false;
#define SALTC1 0x3133731337313373
#define SALTC2 0xd3adb33fd3adb33f
uint64_t gSaltK0 = SALTC1, gSaltK1 = SALTC2;
static uid_t nident_uid;
static gid_t nident_gid;
static bool v4only = false;


static void process_signals()
{
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
    asio_signal_set.add(SIGINT);
    asio_signal_set.add(SIGTERM);
    asio_signal_set.async_wait(
        [](const boost::system::error_code &, int signum) {
            io_service.stop();
        });
}

static int enforce_seccomp(void)
{
    struct sock_filter filter[] = {
        VALIDATE_ARCHITECTURE,
        EXAMINE_SYSCALL,

#if defined(__x86_64__) || (defined(__arm__) && defined(__ARM_EABI__))
        ALLOW_SYSCALL(sendmsg),
        ALLOW_SYSCALL(recvmsg),
        ALLOW_SYSCALL(sendto), // used for glibc syslog routines
        ALLOW_SYSCALL(getpeername),
        ALLOW_SYSCALL(getsockname),
        ALLOW_SYSCALL(connect),
        ALLOW_SYSCALL(socket),
        ALLOW_SYSCALL(accept),
        ALLOW_SYSCALL(fcntl),
#elif defined(__i386__)
        ALLOW_SYSCALL(socketcall),
        ALLOW_SYSCALL(fcntl64),
#else
#error Target platform does not support seccomp-filter.
#endif

        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(epoll_wait),
        ALLOW_SYSCALL(epoll_ctl),
        ALLOW_SYSCALL(stat),
        ALLOW_SYSCALL(open),
        ALLOW_SYSCALL(close),
        ALLOW_SYSCALL(ioctl),
        ALLOW_SYSCALL(rt_sigreturn),
#ifdef __NR_sigreturn
        ALLOW_SYSCALL(sigreturn),
#endif
        // Allowed by vDSO
        ALLOW_SYSCALL(getcpu),
        ALLOW_SYSCALL(time),
        ALLOW_SYSCALL(gettimeofday),
        ALLOW_SYSCALL(clock_gettime),

        // operator new
        ALLOW_SYSCALL(brk),
        ALLOW_SYSCALL(mmap),
        ALLOW_SYSCALL(munmap),

        ALLOW_SYSCALL(exit_group),
        ALLOW_SYSCALL(exit),
        KILL_PROCESS,
    };
    struct sock_fprog prog;
    memset(&prog, 0, sizeof prog);
    prog.len = (unsigned short)(sizeof filter / sizeof filter[0]);
    prog.filter = filter;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        return -1;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
        return -1;
    log_line("seccomp filter installed.  Please disable seccomp if you encounter problems.");
    return 0;
}

static po::variables_map fetch_options(int ac, char *av[])
{
    std::string config_file;

    po::options_description cli_opts("Command-line-exclusive options");
    cli_opts.add_options()
        ("config,c", po::value<std::string>(&config_file),
         "path to configuration file")
        ("background", "run as a background daemon")
        ("quiet,q", "don't print to std(out|err) or log")
        ("help,h", "print help message")
        ("version,v", "print version information")
        ;

    po::options_description gopts("Options");
    gopts.add_options()
        ("paranoid,p",
         "return UNKNOWN-ERROR for all errors except INVALID-PORT (prevents inference of used ports)")
        ("pidfile,f", po::value<std::string>(),
         "path to process id file")
        ("chroot,C", po::value<std::string>(),
         "path in which nident should chroot itself")
        ("max-bytes,b", po::value<int>(),
         "maximum number of bytes allowed from a client")
        ("address,a", po::value<std::vector<std::string> >()->composing(),
         "'address[:port]' on which to listen (default all local)")
        ("user,u", po::value<std::string>(),
         "user name that nident should run as")
        ("salt,s", po::value<std::string>(),
         "string that should be used as salt for hash replies")
        ("disable-ipv6", "host kernel doesn't support ipv6")
        ("seccomp-enforce,S", "enforce seccomp syscall restrictions")
        ;

    po::options_description cmdline_options;
    cmdline_options.add(cli_opts).add(gopts);
    po::options_description cfgfile_options;
    cfgfile_options.add(gopts);

    po::positional_options_description p;
    p.add("address", -1);
    po::variables_map vm;
    try {
        po::store(po::command_line_parser(ac, av).
                  options(cmdline_options).positional(p).run(), vm);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
    }
    po::notify(vm);

    if (config_file.size()) {
        std::ifstream ifs(config_file.c_str());
        if (!ifs) {
            std::cerr << "Could not open config file: " << config_file << "\n";
            std::exit(EXIT_FAILURE);
        }
        po::store(po::parse_config_file(ifs, cfgfile_options), vm);
        po::notify(vm);
    }

    if (vm.count("help")) {
        std::cout << "nident " << NIDENT_VERSION << ", ident server.\n"
                  << "Copyright (c) 2010-2013 Nicholas J. Kain\n"
                  << av[0] << " [options] addresses...\n"
                  << gopts << std::endl;
        std::exit(EXIT_FAILURE);
    }
    if (vm.count("version")) {
        std::cout << "nident " << NIDENT_VERSION << ", ident server.\n" <<
            "Copyright (c) 2010-2013 Nicholas J. Kain\n"
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
        std::exit(EXIT_FAILURE);
    }
    return vm;
}

static void process_options(int ac, char *av[])
{
    std::vector<std::string> addrlist;
    std::string pidfile, chroot_path;
    bool use_seccomp(false);

    auto vm(fetch_options(ac, av));

    if (vm.count("paranoid"))
        gParanoid = true;
    if (vm.count("background"))
        gflags_detach = 1;
    if (vm.count("quiet"))
        gflags_quiet = 1;
    if (vm.count("disable-ipv6"))
        v4only = true;
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
        if (nk_uidgidbyname(t.c_str(), &nident_uid, &nident_gid))
            suicide("invalid user '%s' specified", t.c_str());
    }
    if (vm.count("salt")) {
        auto sst = vm["salt"].as<std::string>();
        gSaltK0 = nk::siphash24_hash(SALTC1, SALTC2, sst.c_str(), sst.size());
        gSaltK1 = nk::siphash24_hash(gSaltK0, SALTC1 ^ SALTC2,
                                     sst.c_str(), sst.size());
    }
    if (vm.count("seccomp-enforce"))
        use_seccomp = true;

    if (!addrlist.size()) {
        auto ep = boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v6(), 113);
        listeners.emplace_back(nk::make_unique<ClientListener>(ep));
    } else
        for (const auto &i: addrlist) {
            std::string addr(i);
            int port = 113;
            auto loc = addr.rfind(":");
            if (loc != std::string::npos) {
                auto pstr = addr.substr(loc + 1);
                try {
                    port = boost::lexical_cast<unsigned short>(pstr);
                } catch (const boost::bad_lexical_cast&) {
                    std::cout << "bad port in address '" << addr
                              << "', defaulting to 113" << std::endl;
                }
                addr.erase(loc);
            }
            try {
                auto addy = boost::asio::ip::address::from_string(addr);
                auto ep = boost::asio::ip::tcp::endpoint(addy, port);
                listeners.emplace_back(nk::make_unique<ClientListener>(ep));
            } catch (const boost::system::error_code&) {
                std::cout << "bad address: " << addr << std::endl;
            }
        }

    if (gflags_detach)
        if (daemon(0,0))
            suicide("detaching fork failed");

    if (pidfile.size() && file_exists(pidfile.c_str(), "w"))
        write_pid(pidfile.c_str());

    umask(077);
    process_signals();
    nk_fix_env(nident_uid, 0);

    nlink = nk::make_unique<Netlink>(v4only);
    if (!nlink->open(NETLINK_INET_DIAG))
        suicide("failed to create netlink socket");

    if (chroot_path.size()) {
        nk_set_chroot(chroot_path.c_str());
        gChrooted = true;
    }

    if (nident_uid != 0 || nident_gid != 0)
        nk_set_uidgid(nident_uid, nident_gid);
    if (use_seccomp) {
        if (enforce_seccomp())
            log_warning("seccomp filter cannot be installed");
    }
}

int main(int ac, char *av[])
{
    gflags_log_name = const_cast<char *>("nident");

    process_options(ac, av);

    io_service.run();

    std::exit(EXIT_SUCCESS);
}

