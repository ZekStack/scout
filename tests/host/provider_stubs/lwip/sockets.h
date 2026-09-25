#pragma once
#include <cstdarg>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>

int scout_test_socket(int domain, int type, int protocol);
int scout_test_setsockopt(int fd, int level, int option, const void *value, socklen_t length);
int scout_test_bind(int fd, const sockaddr *address, socklen_t length);
ssize_t scout_test_sendto(
    int fd,
    const void *buffer,
    size_t length,
    int flags,
    const sockaddr *destination,
    socklen_t destinationLength
);
ssize_t scout_test_recvfrom(
    int fd,
    void *buffer,
    size_t length,
    int flags,
    sockaddr *source,
    socklen_t *sourceLength
);
int scout_test_close(int fd);
int scout_test_connect(int fd, const sockaddr *address, socklen_t length);
int scout_test_getsockopt(int fd, int level, int option, void *value, socklen_t *length);
ssize_t scout_test_send(int fd, const void *buffer, size_t length, int flags);
ssize_t scout_test_recv(int fd, void *buffer, size_t length, int flags);
int scout_test_select(
    int nfds,
    fd_set *readfds,
    fd_set *writefds,
    fd_set *exceptfds,
    timeval *timeout
);
int scout_test_fcntl(int fd, int command, ...);

#define socket scout_test_socket
#define setsockopt scout_test_setsockopt
#define bind scout_test_bind
#define sendto scout_test_sendto
#define recvfrom scout_test_recvfrom
#define close scout_test_close
#define connect scout_test_connect
#define getsockopt scout_test_getsockopt
#define send scout_test_send
#define recv scout_test_recv
#define select scout_test_select
#define fcntl scout_test_fcntl
