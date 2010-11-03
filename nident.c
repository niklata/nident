/* nident.c - ident server
 * Time-stamp: <2010-11-03 04:49:31 njk>
 *
 * (c) 2004-2010 Nicholas J. Kain <njkain at gmail dot com>
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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

#include <pwd.h>
#include <grp.h>

#include <signal.h>
#include <errno.h>

#define _GNU_SOURCE
#include <getopt.h>

#include "defines.h"
#include "malloc.h"
#include "log.h"
#include "chroot.h"
#include "pidfile.h"
#include "signals.h"
#include "strl.h"
#include "exec.h"
#include "network.h"
#include "strlist.h"

static char *cmd = NULL, *args = NULL;

static volatile sig_atomic_t pending_exit, pending_reap;

static void sighandler(int sig) {
    switch (sig) {
	case SIGTERM:
	case SIGINT:
	    pending_exit = 1;
	    break;
	case SIGCHLD:
	    pending_reap = 1;
	    break;
    }
}

static void fix_signals(void) {
    disable_signal(SIGPIPE);
    disable_signal(SIGUSR1);
    disable_signal(SIGUSR2);
    disable_signal(SIGTSTP);
    disable_signal(SIGTTIN);
    disable_signal(SIGHUP);

    hook_signal(SIGCHLD, sighandler, 0);
    hook_signal(SIGINT, sighandler, 0);
    hook_signal(SIGTERM, sighandler, 0);
}

static void grim_reaper(void)
{
    while (waitpid(-1, NULL, WNOHANG) > 0);
    pending_reap = 0;
}

static void handle_signals(void)
{
    if (pending_reap)
	grim_reaper();
    if (pending_exit)
	exit(EXIT_SUCCESS);
}

/* Abstracts away the details of accept()ing a socket connection. */
static void accept_conns(int lsock)
{
    int fd;
    struct sockaddr_in sock_addr;
    socklen_t sock_len = sizeof sock_addr;

    for(;;)
    {
	fd = accept(lsock, (struct sockaddr *) &sock_addr, &sock_len);

	if (fd != -1) {
	    // answer request
	}

	switch (errno) {
	    case EAGAIN:
#ifdef LINUX
	    case ENETDOWN:
	    case EPROTO:
	    case ENOPROTOOPT:
	    case EHOSTDOWN:
	    case ENONET:
	    case EHOSTUNREACH:
	    case EOPNOTSUPP:
	    case ENETUNREACH:
#endif
		return;

	    case EINTR:
		continue;

	    case EBADF:
	    case ENOTSOCK:
	    case EINVAL:
	    case ECONNABORTED:
	    case EMFILE:
	    case ENFILE:
		log_line("warning: accept returned %s!", strerror(errno));
		return;

	    default:
		log_line("warning: accept returned a mysterious error: %s",
			 strerror(errno));
		return;
	}
    }
}

#ifdef LINUX
#include <sys/epoll.h>
static int epollfd;
static struct epoll_event ev, *events;
static int max_ev_events = 4;

static void epoll_init(int *sockets)
{
    epollfd = epoll_create1(0);
    if (epollfd == -1)
        suicide("epoll_create1 failed");
    events = xmalloc(max_ev_events * sizeof (struct epoll_event));

    for (int i = 1; i < sockets[0]; ++i) {
	if (sockets[i] < 0)
	    continue;
	ev.events = EPOLLIN;
	ev.data.fd = sockets[i];
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sockets[i], &ev) == -1)
	    suicide("epoll_ctl failed");
    }
    free(sockets);
}

static void epoll_dispatch_work(void)
{
    for (;;) {
	handle_signals();

	int ret = epoll_wait(epollfd, events, max_ev_events, -1);
	if (ret == -1) {
	    if (errno == EINTR)
		continue;
	    else
		suicide("epoll_wait failed");
	}
	if (pending_exit == 1)
	    return;
	for (int i = 0; i < ret; ++i)
	    accept_conns(events[i].data.fd);
    }
}
#else /* LINUX */
static void select_dispatch_work(int *sockets)
{
    fd_set rfds;
    int maxfdn = -1;
    for (int i = 1; i < sockets[0]; ++i) {
	if (sockets[i] > maxfdn)
	    maxfdn = sockets[i];
    }

    for (;;) {
	handle_signals();

	FD_ZERO(&rfds);
	for (int i = 1; i < sockets[0]; ++i) {
	    if (sockets[i] < 0)
		continue;
	    FD_SET(sockets[i], &rfds);
	}

	if (select(maxfdn + 1, &rfds, NULL, NULL, NULL) == -1) {
	    if (errno == EINTR)
		continue;
	    if (pending_exit == 1)
		return;
	    suicide("select returned an error");
	}

        /* handle pending connections */
	for (int i = 1; i < sockets[0]; ++i) {
	    if (sockets[i] < 0)
		continue;
	    if (FD_ISSET(sockets[i], &rfds))
		accept_conns(sockets[i]);
	}
    }
}
#endif /* LINUX */

int main(int argc, char** argv) {
    int c, t, uid = 0, gid = 0, i, len;
    unsigned int port = 0;
    int backlog = 30;
    char *pidfile = NULL;
    char *chrootd = NULL;
    char *p;
    struct passwd *pws;
    struct group *grp;
    strlist_t *addrlist = NULL;
    int *sockets = NULL;

    gflags_log_name = "nident";

    while (1) {
	int option_index = 0;
	static struct option long_options[] = {
	    {"detach", 0, 0, 'd'},
	    {"nodetach", 0, 0, 'n'},
	    {"pidfile", 1, 0, 'f'},
	    {"quiet", 0, 0, 'q'},
	    {"chroot", 1, 0, 'c'},
	    {"max-events", 1, 0, 'e'},
	    {"backlog", 1, 0, 'b'},
	    {"address", 1, 0, 'a'},
	    {"port", 1, 0, 'p'},
	    {"user", 1, 0, 'u'},
	    {"group", 1, 0, 'g'},
	    {"help", 0, 0, 'h'},
	    {"version", 0, 0, 'v'},
	    {0, 0, 0, 0}
	};

	c = getopt_long(argc, argv, "dnf:qc:"
#ifdef LINUX
			"e:"
#endif
		        "b:a:p:ou:g:hv",
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
		    "  -q, --quiet                 don't print to std(out|err) or log\n"
		    "  -c, --config-dir                configuration directory\n");
#ifdef LINUX
		printf(
		    "  -e, --max-events            max events processed per epoll_wait\n");
#endif
		printf(
		    "  -b, --backlog               maximum simultaneous connections accepted\n"
		    "  -a, --address               address on which to listen (default all local)\n"
		    "  -p, --port                  port on which to listen (only one allowed)\n"
		    "  -f, --pidfile               pidfile path\n");
		printf(
		    "  -u, --user                  user name that nident should run as\n"
		    "  -g, --group                 group name that nident should run as\n"
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

	    case 'b':
		backlog = atoi(optarg);
		break;

	    case 'p':
		port = atoi(optarg);
		break;

	    case 'c':
		len = strlen(optarg) + 1;
		free(chrootd);
		chrootd = xmalloc(len);
		strlcpy(chrootd, optarg, len);
		break;

	    case 'f':
		len = strlen(optarg) + 1;
		free(pidfile);
		pidfile = xmalloc(len);
		strlcpy(pidfile, optarg, len);
		break;

	    case 'a':
		add_to_strlist(&addrlist, optarg);
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
#ifdef LINUX
	    case 'e':
		max_ev_events = atoi(optarg);
		break;
#endif
	}
    }

    if (argv[optind] != NULL) {
	len = strlen(argv[optind]) + 1;
	cmd = xmalloc(len);
	strlcpy(cmd, argv[optind], len);

	for (len = 0, i = optind + 1; argv[i] != NULL; ++i)
	    len += strlen(argv[i]) + 1; /* +1 accounts for space AND '\0' */
	if (len) {
	    args = xmalloc(len);
	    i = optind + 1;
	    strlcpy(args, argv[i++], len);
	    while (argv[i] != NULL) {
		strlcat(args, " ", len);
		strlcat(args, argv[i++], len);
	    }
	}
    }
    if (gflags_detach)
	if (daemon(0,0))
	    suicide("detaching fork failed");

    if (!cmd)
	suicide("no server daemon to run!");

    if (!port)
	suicide("no listening port specified!");

    if (pidfile && file_exists(pidfile, "w"))
	write_pid(pidfile);

    umask(077);
    fix_signals();
    ncm_fix_env(uid, 0);
    if (!addrlist)
	sockets = tcp_server_socket("::", port, backlog);
    else {
	for (strlist_t *iter = addrlist; iter; iter = iter->next) {
	    int *t;
	    t = tcp_server_socket(iter->str, port, backlog);
	    if (!sockets) {
		sockets = t;
		continue;
	    }
	    int newsize = sockets[0] + t[0] - 1;
	    sockets = xrealloc(sockets, newsize);
	    for (int i = sockets[0], j = 1; i < newsize; ++i, ++j)
		sockets[i] = t[j];
	    sockets[0] = newsize;
	    free(t);
	}
	free_strlist(addrlist);
    }
    if (sockets == NULL)
	suicide("unable to create any listen sockets");

    imprison(chrootd);
    drop_root(uid, gid, NULL);

    /* Cover our tracks... */
    free(chrootd);
    free(pidfile);
    chrootd = NULL;
    pidfile = NULL;

    close(0);
    close(1);

#ifdef LINUX
    epoll_init(sockets);
    epoll_dispatch_work();
#else
    select_dispatch_work(sockets);
    free(sockets);
#endif

    exit(EXIT_SUCCESS);
}

