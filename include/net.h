#ifndef NET_H
#define NET_H

#include "tachyon.h"

int net_create_listener(int port, const char *bind_addr);
int net_attach_cpu_steering(int fd, int nsock);
int net_get_max_fds(void);

#endif /* NET_H */
