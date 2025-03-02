#ifndef SCAN_H
#define SCAN_H

#include "parse.h"
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/types.h>

#define MAX_EVENTS 256
#define TIMEOUT 5

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
int print_ports(int *start, int *prev, int curr);

// Handles errors from connect,
// returning -1 if the program is to
// fail and 0 otherwise.
int print_error(char *port_status, int err);

// Iterates through the port range
// specified and scans the supplied
// IP address at each port.
int scan_ports(char **dest, int *p_start, int *p_end);

// Creates a non-blocking socket
// and initiates a TCP connection.
// Returns the file discriptor
// of the new socket or 0 if an
// immediate connection is formed.
int scan_port(char **dest, int p, int efd);

#endif // SCAN_H