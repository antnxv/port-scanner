#ifndef SCANNER_IO_H
#define SCANNER_IO_H

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

// Prints usage information to the specified stream.
void print_usage(FILE *stream);

// Determines range of ports provided to program.
int arg_ports(struct sockaddr_in *dest, char const *arg, int *p_max);

// Converts provided IP address to
// network-byte-order in_addr_t.
int arg_ip(struct sockaddr_in *dest, char const *arg);

// Parses arguments passed to program, gathering
// destination IP address, ports and an optional
// output file.
int parse_args(int argc, char const *argv[], int *p_max, struct sockaddr_in *dest, char **ifilename, char **ofilename);

// Exits with status 1 if no arguments were passed
// to the program, if an IP was passed with no ports
// or vice-versa, if the specified input or output
// files are inaccessible.
void check_args(struct sockaddr_in *dest, int *p_max, char **ifilename, char **ofilename, FILE **istream, int *ofd);

// Parses line of input file for destination IP
// addresses and port ranges.
int parse_line(char **line, int n_line, struct sockaddr_in *dest, int *p_max, char **ifilename);

#endif // SCANNER_IO_H