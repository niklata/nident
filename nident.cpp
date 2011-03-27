/* nident.c - ident server
 * Time-stamp: <2011-03-26 23:54:01 nk>
 *
 * (c) 2004-2011 Nicholas J. Kain <njkain at gmail dot com>
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

#include "identclient.hpp"

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

boost::asio::io_service io_service;

bool gParanoid = false;

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

int main(int argc, char** argv) {
    int c, t, uid = 0, gid = 0, len;
    unsigned int port = 0;
    std::string pidfile;
    char *p;
    struct passwd *pws;
    struct group *grp;
    std::vector<ClientListener *> listeners;
    std::vector<std::string> addrlist;

    gflags_log_name = const_cast<char *>("nident");

    while (1) {
	int option_index = 0;
	static struct option long_options[] = {
	    {"detach", 0, 0, 'd'},
	    {"nodetach", 0, 0, 'n'},
	    {"pidfile", 1, 0, 'f'},
	    {"quiet", 0, 0, 'q'},
	    {"max-bytes", 1, 0, 'B'},
	    {"address", 1, 0, 'a'},
	    {"port", 1, 0, 'p'},
	    {"user", 1, 0, 'u'},
	    {"group", 1, 0, 'g'},
	    {"paranoid", 0, 0, 'P'},
	    {"help", 0, 0, 'h'},
	    {"version", 0, 0, 'v'},
	    {0, 0, 0, 0}
	};

	c = getopt_long(argc, argv, "dnf:qB:a:p:ou:g:Phv",
			long_options, &option_index);
	if (c == -1)
	    break;

	switch (c) {

	    case 'h':
		printf("nident %s, ident server.\n", NIDENT_VERSION);
		printf(
		    "Copyright (c) 2010 Nicholas J. Kain\n"
		    "Usage: nident [OPTIONS]\n"
		    "  -d, --detach                detach from TTY and daemonize (default)\n"
		    "  -n, --nodetach              stay attached to TTY\n"
		    "  -q, --quiet                 don't print to std(out|err) or log\n");
		printf(
		    "  -B, --max-bytes             maximum number of bytes allowed from a client\n"
		    "  -a, --address               address on which to listen (default all local)\n"
		    "  -p, --port                  port on which to listen (only one allowed)\n"
		    "  -f, --pidfile               pidfile path\n");
		printf(
		    "  -u, --user                  user name that nident should run as\n"
		    "  -g, --group                 group name that nident should run as\n"
		    "  -P, --paranoid              return UNKNOWN-ERROR for all errors except\n"
                    "                              INVALID-PORT (prevents inference of used ports)\n"
		    "  -h, --help                  print this help and exit\n"
		    "  -v, --version               print license information and exit\n");
		exit(EXIT_FAILURE);
		break;

	    case 'v':
		printf("nident %s, ident server.\n", NIDENT_VERSION);
		printf(
		    "Copyright (c) 2010 Nicholas J. Kain\n"
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
		    "POSSIBILITY OF SUCH DAMAGE.\n");
		exit(EXIT_FAILURE);
		break;

	    case 'd':
		gflags_detach = 1;
		break;

	    case 'n':
		gflags_detach = 0;
		break;

	    case 'q':
		gflags_quiet = 1;
		break;

	    case 'B':
		max_client_bytes = atoi(optarg);
		if (max_client_bytes < 64)
		    max_client_bytes = 64;
		else if (max_client_bytes > 1024)
		    max_client_bytes = 1024;
		break;

	    case 'p':
		port = atoi(optarg);
		break;

	    case 'f':
		len = strlen(optarg);
		pidfile = std::string(optarg, len);
		break;

	    case 'a':
		len = strlen(optarg);
		addrlist.push_back(std::string(optarg, len));
		break;

	    case 'u':
		t = (unsigned int) strtol(optarg, &p, 10);
		if (*p != '\0') {
		    pws = getpwnam(optarg);
		    if (pws) {
			uid = (int)pws->pw_uid;
			if (!gid)
			    gid = (int)pws->pw_gid;
		    } else suicide("invalid uid specified");
		} else
		    uid = t;
		break;

	    case 'g':
		t = (unsigned int) strtol(optarg, &p, 10);
		if (*p != '\0') {
		    grp = getgrnam(optarg);
		    if (grp) {
			gid = (int)grp->gr_gid;
		    } else suicide("invalid gid specified");
		} else
		    gid = t;
		break;

	    case 'P':
		gParanoid = true;
		break;
	}
    }

    if (gflags_detach)
	if (daemon(0,0))
	    suicide("detaching fork failed");

    if (!port)
	suicide("no listening port specified!");

    if (pidfile.size() && file_exists(pidfile.c_str(), "w"))
	write_pid(pidfile.c_str());

    umask(077);
    fix_signals();
    ncm_fix_env(uid, 0);

    if (!addrlist.size()) {
	auto ep = boost::asio::ip::tcp::endpoint();
	ep.port(port);
	auto cl = new ClientListener(ep);
	listeners.push_back(cl);
    } else
	for (auto i = addrlist.cbegin(); i != addrlist.cend(); ++i) {
	    auto addy = boost::asio::ip::address::from_string(*i);
	    auto ep = boost::asio::ip::tcp::endpoint(addy, port);
	    auto cl = new ClientListener(ep);
	    listeners.push_back(cl);
	}
    addrlist.clear();

    if (uid != 0 || gid != 0)
	drop_root(uid, gid);

    /* Cover our tracks... */
    pidfile.clear();

    io_service.run();

    exit(EXIT_SUCCESS);
}

