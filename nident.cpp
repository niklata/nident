/* nident.c - ident server
 * Time-stamp: <2010-11-03 11:40:00 nk>
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

#include <string>
#include <map>

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
#include <sys/epoll.h>
#include <fcntl.h>
#include <ctype.h>

#include <pwd.h>
#include <grp.h>

#include <signal.h>
#include <errno.h>
#include <getopt.h>

extern "C" {
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
}

static unsigned int max_client_bytes = 128;

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

static void unschedule_read(int fd);
static void schedule_write(int fd);

class IdentClient {
public:
    IdentClient(int fd) : fd_(fd) {
	state_ = STATE_WAITIN;
	server_port_ = 0;
	client_port_ = 0;
    }
    ~IdentClient() {
	close(fd_);
	log_line("fd %d: destructor called", fd_);
    }
    enum IdentClientState {
	STATE_WAITIN,
	STATE_GOTIN,
	STATE_WAITOUT,
	STATE_DONE
    };
    const int fd_;
    std::string inbuf_;
    std::string outbuf_;
    IdentClientState state_;

    int server_port_;
    int client_port_;

    bool process_input();
    bool parse_request();
    bool create_reply();
    bool process_output();
};

// Returns false if the object needs to be destroyed by the caller.
// State can change: STATE_WAITIN -> STATE_GOTIN
bool IdentClient::process_input()
{
    if (state_ != STATE_WAITIN)
	return false;
    char buf[max_client_bytes];
    memset(buf, 0, sizeof buf);
    ssize_t len = read(fd_, buf, sizeof buf);
    if (len == -1) {
	log_line("fd %i: read() error %d", fd_, strerror(errno));
	return false;
    }
    for (int i = 0; i < len; ++i) {
	if (buf[i] == '\n' || buf[i] == '\r') {
	    state_ = STATE_GOTIN;
	    break;
	}
	if (inbuf_.size() + 1 > max_client_bytes) {
	    log_line("fd %i: flood from peer (more than %i bytes), closing",
		     fd_, max_client_bytes);
	    return false;
	}
	inbuf_ += buf[i];
    }
    if (state_ == STATE_GOTIN) {
	if (!create_reply())
	    return false;
    }
    return true;
}

// Returns false if the object needs to be destroyed by the caller.
bool IdentClient::parse_request()
{
    enum ParseState {
	ParseInvalid,
	ParseServerPort,
	ParseClientPort,
	ParseDone
    } state = ParseServerPort;
    int prev_idx = 0;
    size_t i;
    bool found_num = false;
    bool found_ws_after_num = false;
    for (i = 0; i < inbuf_.size(); ++i) {
	const char c = inbuf_.at(i);
	if (state == ParseServerPort) {
	    log_line("c is '%c'", c);
	    switch (c) {
		case ' ':
		case '\t':
		    log_line("ws");
		    if (found_num)
			found_ws_after_num = true;
		    continue;
		case ',': {
		    std::string cport = inbuf_.substr(prev_idx, i);
		    client_port_ = atoi(cport.c_str());
		    state = ParseClientPort;
		    prev_idx = i + 1;
		    found_num = false;
		    found_ws_after_num = false;
		    log_line("cport: %d", client_port_);
		    continue;
		}
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
		    if (found_num == false) {
			found_num = true;
			prev_idx = i;
		    }
		    if (found_ws_after_num) {
			state = ParseInvalid;
			log_line("!");
			return false;
		    }
		    log_line("#");
		    continue;
		default:
		    state = ParseInvalid;
		    log_line("!");
		    return false;
	    }
	} else if (state == ParseClientPort) {
	    log_line("c is '%c'", c);
	    switch (c) {
		case ' ':
		case '\t':
		    log_line("ws");
		    if (found_num)
			found_ws_after_num = true;
		    continue;
		case '\r':
		case '\n': {
		    std::string sport = inbuf_.substr(prev_idx, i);
		    server_port_ = atoi(sport.c_str());
		    state = ParseDone;
		    log_line("sport: %d", server_port_);
		    return true;
		}
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
		    if (found_num == false) {
			found_num = true;
			prev_idx = i;
		    }
		    if (found_ws_after_num) {
			state = ParseInvalid;
			log_line("!");
			return false;
		    }
		    log_line("#");
		    continue;
		default:
		    state = ParseInvalid;
		    log_line("!");
		    return false;
	    }
	}
    }
    log_line("state: %d", state);
    if (state == ParseClientPort && found_num) {
	log_line("... prev_idx: %d, i: %d", prev_idx, i);
	std::string sport = inbuf_.substr(prev_idx, i);
	log_line("sport string: %s", sport.c_str());
	server_port_ = atoi(sport.c_str());
	state = ParseDone;
	log_line("sport: %d", server_port_);
	return true;
    }
    return false;
}

// Forms a reply and schedules a write.
// State can change: STATE_GOTIN -> STATE_WAITOUT
bool IdentClient::create_reply()
{
    outbuf_.clear();
    if (!parse_request()) {
	return false;
    }
    log_line("serverport: %i\t clientport: %i", server_port_, client_port_);
    // XXX: do real work for a real response
    outbuf_ = "0,0:ERROR:NO-USER\r\n";
    state_ = STATE_WAITOUT;
    unschedule_read(fd_);
    schedule_write(fd_);
    return true;
}

// Returns false if the object needs to be destroyed by the caller.
// State can change: STATE_WAITOUT -> STATE_DONE
bool IdentClient::process_output()
{
  repeat:
    int written = write(fd_, outbuf_.c_str(), outbuf_.size());
    if (written == -1) {
	if (errno == EAGAIN)
	    goto repeat;
	log_line("fd %i: write() error %s", strerror(errno));
	return false;
    }
    outbuf_.erase(0, written);
    if (outbuf_.size() == 0) {
	state_ = STATE_DONE;
	return false;
    }
    return true;
}

static std::map<int, IdentClient *> clientmap;

static int epollfd;
static struct epoll_event *events;
static int max_ev_events = 4;

static void schedule_read(int fd)
{
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev) == -1)
	suicide("schedule_read: epoll_ctl failed");
}

static void unschedule_read(int fd)
{
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    if (epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, &ev) == -1)
	suicide("unschedule_read: epoll_ctl failed");
}

static void schedule_write(int fd)
{
    struct epoll_event ev;
    ev.events = EPOLLOUT;
    ev.data.fd = fd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev) == -1)
	suicide("schedule_write: epoll_ctl failed");
}

static void unschedule_write(int fd)
{
    struct epoll_event ev;
    ev.events = EPOLLOUT;
    ev.data.fd = fd;
    if (epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, &ev) == -1)
	suicide("unschedule_write: epoll_ctl failed");
}

/* Abstracts away the details of accept()ing a socket connection. */
static void accept_conns(int lsock)
{
    struct sockaddr_in sock_addr;
    socklen_t sock_len = sizeof sock_addr;

    for(;;)
    {
	log_line("accept(lsock = %i)", lsock);
	int fd = accept(lsock, (struct sockaddr *) &sock_addr, &sock_len);

	if (fd != -1) {
	    IdentClient *cid = new IdentClient(fd);
	    clientmap[fd] = cid;
	    schedule_read(fd);
	    return;
	}

	switch (errno) {
	    case EAGAIN:
	    case ENETDOWN:
	    case EPROTO:
	    case ENOPROTOOPT:
	    case EHOSTDOWN:
	    case ENONET:
	    case EHOSTUNREACH:
	    case EOPNOTSUPP:
	    case ENETUNREACH:
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
		sleep(1);
		return;

	    default:
		log_line("warning: accept returned a mysterious error: %s",
			 strerror(errno));
		return;
	}
    }
}

static void epoll_init(int *sockets)
{
    struct epoll_event ev;
    epollfd = epoll_create1(0);
    if (epollfd == -1)
        suicide("epoll_create1 failed");
    events = new struct epoll_event[max_ev_events];

    for (int i = 1; i < sockets[0]; ++i) {
	if (sockets[i] < 0)
	    continue;
	ev.events = EPOLLIN;
	ev.data.fd = sockets[i];
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sockets[i], &ev) == -1)
	    suicide("epoll_ctl failed");
	log_line("added lsock = %i", sockets[i]);
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
	for (int i = 0; i < ret; ++i) {
	    int fd = events[i].data.fd;
	    log_line("events[%i].data.fd = %i", i, fd);
	    std::map<int, IdentClient *>::iterator iter = clientmap.find(fd);
	    if (iter == clientmap.end()) {
		if (events[i].events & EPOLLIN)
		    accept_conns(fd);
		else if (events[i].events & EPOLLHUP)
		    suicide("listen fd got a HUP");
	    } else {
		if (events[i].events & EPOLLIN) {
		    IdentClient *id = iter->second;
		    if (!id->process_input()) {
			unschedule_read(fd);
			clientmap.erase(iter);
			delete id;
			continue;
		    }
		}
		else if (events[i].events & EPOLLOUT) {
		    IdentClient *id = iter->second;
		    if (!id->process_output()) {
			unschedule_write(fd);
			clientmap.erase(iter);
			delete id;
			continue;
		    }
		} else if (events[i].events & EPOLLHUP) {
		    IdentClient *id = iter->second;
		    if (id->state_ == IdentClient::STATE_WAITIN)
			unschedule_read(fd);
		    else if (id->state_ == IdentClient::STATE_WAITOUT)
			unschedule_write(fd);
		    clientmap.erase(iter);
		    delete id;
		    continue;
		}
	    }
	}
    }
}

int main(int argc, char** argv) {
    int c, t, uid = 0, gid = 0, len;
    unsigned int port = 0;
    int backlog = 30;
    std::string pidfile, chrootd;
    char *p;
    struct passwd *pws;
    struct group *grp;
    strlist_t *addrlist = NULL;
    int *sockets = NULL;

    gflags_log_name = const_cast<char *>("nident");

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
	    {"max-bytes", 1, 0, 'B'},
	    {"address", 1, 0, 'a'},
	    {"port", 1, 0, 'p'},
	    {"user", 1, 0, 'u'},
	    {"group", 1, 0, 'g'},
	    {"help", 0, 0, 'h'},
	    {"version", 0, 0, 'v'},
	    {0, 0, 0, 0}
	};

	c = getopt_long(argc, argv, "dnf:qc:e:b:B:a:p:ou:g:hv",
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
		    "  -c, --config-dir                configuration directory\n"
		    "  -e, --max-events            max events processed per epoll_wait\n");
		printf(
		    "  -b, --backlog               maximum simultaneous connections accepted\n"
		    "  -B, --max-bytes             maximum number of bytes allowed from a client\n"
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

	    case 'c':
		len = strlen(optarg);
		chrootd = std::string(optarg, len);
		break;

	    case 'f':
		len = strlen(optarg);
		pidfile = std::string(optarg, len);
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

	    case 'e':
		max_ev_events = atoi(optarg);
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

    if (!addrlist)
	sockets = tcp_server_socket("::", port, backlog);
    else {
	for (strlist_t *iter = addrlist; iter;
	     iter = static_cast<strlist_t *>(iter->next)) {
	    int *t;
	    t = tcp_server_socket(iter->str, port, backlog);
	    if (!sockets) {
		sockets = t;
		continue;
	    }
	    int newsize = sockets[0] + t[0] - 1;
	    sockets = static_cast<int *>(xrealloc(sockets, newsize));
	    for (int i = sockets[0], j = 1; i < newsize; ++i, ++j)
		sockets[i] = t[j];
	    sockets[0] = newsize;
	    free(t);
	}
	free_strlist(addrlist);
    }
    if (sockets == NULL)
	suicide("unable to create any listen sockets");

    //imprison(chrootd.c_str());

    if (uid != 0 || gid != 0)
	drop_root(uid, gid);

    /* Cover our tracks... */
    chrootd.clear();
    pidfile.clear();

    epoll_init(sockets);
    epoll_dispatch_work();

    exit(EXIT_SUCCESS);
}

