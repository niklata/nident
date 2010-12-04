/* epoll.cpp - ident server event handling
 * Time-stamp: <2010-12-03 23:58:04 njk>
 *
 * (c) 2010 Nicholas J. Kain <njkain at gmail dot com>
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

#include <map>

#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/signalfd.h>

#include "identclient.hpp"
#include "epoll.hpp"

extern "C" {
#include "network.h"
#include "log.h"
#include "io.h"
}

#include <signal.h>
extern int gSignalFd;

static std::map<int, IdentClient *> clientmap;

static int epollfd;
static struct epoll_event *events;
int max_ev_events;

void epoll_add(int fd)
{
    struct epoll_event ev;
    int r;
    ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
    ev.data.fd = fd;
    r = epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev);
    if (r == -1) {
        suicide("epoll_add failed %s", strerror(errno));
    }
}

void epoll_del(int fd)
{
    struct epoll_event ev;
    int r;
    ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
    ev.data.fd = fd;
    r = epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, &ev);
    if (r == -1) {
        suicide("epoll_del failed %s", strerror(errno));
    }
}

void epoll_set_write(int fd)
{
    struct epoll_event ev;
    int r;
    ev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
    ev.data.fd = fd;
    r = epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &ev);
    if (r == -1) {
        suicide("epoll_set_write failed %s", strerror(errno));
    }
}

void epoll_unset_write(int fd)
{
    struct epoll_event ev;
    int r;
    ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
    ev.data.fd = fd;
    r = epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &ev);
    if (r == -1) {
        suicide("epoll_unset_write failed %s", strerror(errno));
    }
}

/* Abstracts away the details of accept()ing a socket connection. */
static void accept_conns(int lsock)
{
    struct sockaddr_in sock_addr;
    socklen_t sock_len = sizeof sock_addr;

    for(;;)
    {
        int fd = accept(lsock, (struct sockaddr *) &sock_addr, &sock_len);

        if (fd != -1) {
            IdentClient *cid = new IdentClient(fd);
            clientmap[fd] = cid;
            tcp_set_sock_nonblock(fd);
            epoll_add(fd);
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

void epoll_init(int *sockets)
{
    struct epoll_event ev;
    epollfd = epoll_create1(0);
    if (epollfd == -1)
        suicide("epoll_create1 failed");
    events = new struct epoll_event[max_ev_events];

    // Initialize the listen server sockets.
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

void epoll_dispatch_work(void)
{
    for (;;) {
        int ret = epoll_wait(epollfd, events, max_ev_events, -1);
        if (ret == -1) {
            if (errno == EINTR)
                continue;
            else
                suicide("epoll_wait failed");
        }
        for (int i = 0; i < ret; ++i) {
            int fd = events[i].data.fd;
            if (fd == gSignalFd) {
                struct signalfd_siginfo si;
                safe_read(gSignalFd, (char *)&si, sizeof si);
                switch (si.ssi_signo) {
                    case SIGTERM:
                    case SIGINT:
                        return;
                    case SIGCHLD:
                        while (waitpid(-1, NULL, WNOHANG) > 0);
                        break;
                }
                continue;
            }
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
                        clientmap.erase(iter);
                        delete id;
                        continue;
                    }
                } else if (events[i].events & EPOLLOUT) {
                    IdentClient *id = iter->second;
                    if (!id->process_output()) {
                        clientmap.erase(iter);
                        delete id;
                        continue;
                    }
                } else if (events[i].events & EPOLLHUP ||
                           events[i].events & EPOLLRDHUP ||
                           events[i].events & EPOLLERR) {
                    IdentClient *id = iter->second;
                    clientmap.erase(iter);
                    delete id;
                    continue;
                }
            }
        }
    }
}
