#include "scanner_io.h"

void print_usage(FILE *stream) {
    fprintf(stream, "Usage: portscan OPTIONS\n");
    fprintf(stream, "--ports (-p) START[:END]: Port (range) to scan. Default 1-1024, valid 1-65535.\n");
    fprintf(stream, "--ip (-i) IP_ADDR: IP Address to scan. Default localhost.\n");
    fprintf(stream, "--input (-list, -l) FILENAME: List of IP Addresses and ports to iteratively scan.\n");
    fprintf(stream, "--output (-o) FILENAME: Optional output file.\n");
    fprintf(stream, "Must specify either an input list or both a port (range) and IP address, but not both!\n");
    fflush(stream);
}

int arg_ports(struct sockaddr_in *dest, char const *arg, int *p_max) {
    char *p_hyph;

    dest->sin_port = strtol(arg, &p_hyph, 0);
    if (dest->sin_port < 1 || dest->sin_port > 65535) {
        fprintf(stderr, "portscan: %d: Port must be between an integer 1 and 65535", dest->sin_port);
        fflush(stderr);
        exit(1);
    }

    if (p_hyph == NULL) {
        *p_max = dest->sin_port;
        return 0;
    } else if (*p_hyph != '-') {
        fprintf(stderr, "portscan: %c: Syntax error.\n", *p_hyph);
        fflush(stderr);
        exit(1);
    }
    
    *p_max = strtol(p_hyph + 1, &p_hyph, 0);
    if (*p_max < 1 || *p_max > 65535) {
        fprintf(stderr, "portscan: %d: Port must be between an integer 1 and 65535", *p_max);
        fflush(stderr);
        exit(1);
    }

    if (p_hyph != NULL) {
        fprintf(stderr, "portscan: %c: Syntax error.\n", *p_hyph);
        fflush(stderr);
        exit(1);
    }
    
    return 0;
}

int arg_ip(struct sockaddr_in *dest, char const *arg) {

}

int parse_args(int argc, char const *argv[], int *p_max, struct sockaddr_in *dest, char **ifilename, char **ofilename){

}

void check_args(struct sockaddr_in *dest, int *p_max, char **ifilename, char **ofilename, int *ifd, int *ofd){

}

int parse_list(char *filename){

}