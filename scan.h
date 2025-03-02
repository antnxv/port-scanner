#ifndef SCAN_H
#define SCAN_H

#include "parse.h"
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/types.h>

#define MAX_EVENTS 256
#define TIMEOUT 750

// Simultaneous storage of ports and
// socket file descriptors in events.
struct sp {
    int s;
    int p;
};

// Prints open ports but batches
// port ranges with unknown services.
//  curr = 0 forces print,
//  start = 0 starts new range
// Returns 0 if printed, -1 if not.
int print_ports(int *start, int *prev, int curr, int *print_start);

// Handles errors from connect,
// exiting with status 1 on
// system/process errors
int print_error(long *port_status, int err);

// Iterates through the port range
// specified and scans the supplied
// IP address at each port.
// Returns 0 on immediate connection
// or a pointer to the dynamically
// allocated epoll data structure
// for subsequent freeing.
int scan_ports(char **dest, int *p_start, int *p_end);

// Creates a non-blocking socket
// and initiates a TCP connection.
// Returns a pointer to the socket's
// allocated event data or 0 if an
// immediate connection is formed.
long scan_port(char **dest, int p, int efd);

#endif // SCAN_H