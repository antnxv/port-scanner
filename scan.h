#ifndef SCAN_H
#define SCAN_H

#include "parse.h"
#include <netdb.h>
#include <sys/types.h>

// Prints open ports but batches
// port ranges with unknown services.
//  curr = 0 forces print,
//  start = 0 starts new range
// Returns 0 if printed, -1 if not.
int print_ports(int *start, int *prev, int curr);

// Iterates through the port range
// specified and scans the supplied
// IP address at each port.
int scan_ports(char **dest, int *p_start, int *p_end);

// Binds address and port to a socket
// and attempts to connect via TCP,
// returning the status of the
// connection formed
// (0 for open, -1 for closed)
int scan_port(char **dest, int p);

#endif // SCAN_H