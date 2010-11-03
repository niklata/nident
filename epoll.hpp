#ifndef NK_EPOLL_H_
#define NK_EPOLL_H_

void schedule_read(int fd);
void unschedule_read(int fd);
void schedule_write(int fd);
void unschedule_write(int fd);
void epoll_init(int *sockets);
void epoll_dispatch_work(void);

extern int max_ev_events;

#endif /* NK_EPOLL_H_ */
