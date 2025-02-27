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

// Handles errors from connect,
// returning -1 if the program is to
// fail and 0 otherwise.
int print_error(int *port_status);

// Iterates through the port range
// specified and scans the supplied
// IP address at each port.
int scan_ports(char **dest, int *p_start, int *p_end);

// Creates a non-blocking socket
// and attempts to connect via TCP,
// polling until return and reporting
// the status of the connection
// (0 for open, -1 for closed)
int scan_port(char **dest, int p);

#endif // SCAN_H