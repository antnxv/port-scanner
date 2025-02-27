#ifndef PARSE_H
#define PARSE_H

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
int arg_ports(char const *arg, int *p_start, int *p_end);

// Parses arguments passed to program, gathering
// destination IP address, ports and an optional
// output file.
int parse_args(int argc, char const *argv[], char **dest, int *p_start, int *p_end, char **ifilename, char **ofilename);

// Exits with status 1 if no arguments were passed
// to the program, if an IP was passed with no ports
// or vice-versa, if the specified input or output
// files are inaccessible.
void check_args(char **dest, int *p_start, int *p_end, char **ifilename, char **ofilename, FILE **istream, int *ofd);

// Parses line of input file for destination IP
// addresses and port ranges.
int parse_line(char **line, int n_line, char **dest, int *p_start, int *p_end, char **ifilename);

#endif // PARSE_H