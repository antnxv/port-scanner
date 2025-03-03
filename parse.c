#include "parse.h"

void print_usage(FILE *stream) {
    fprintf(stream, "+---------------------------------------------------+\n");
    fprintf(stream, "Usage: portscan OPTIONS\n\n");
    fprintf(stream, "--ports (-p) START[:END]\n Port (range) to scan. Default 1-1024, valid 1-65535.\n");
    fprintf(stream, " Do not supply an input file.\n\n");
    fprintf(stream, "--ip (-i) IP_ADDR\n IP Address to scan. Default localhost.\n");
    fprintf(stream, " Do not supply an input file.\n\n");
    fprintf(stream, "--input (--list, -l) FILENAME\n List of IP Addresses and ports to iteratively scan.\n");
    fprintf(stream, " Entries must be of the format IP_ADDR\\tPORT_START\\tPORT_END.\n\n");
    fprintf(stream, " Do not supply IP or port(s) to command line.\n\n");
    fprintf(stream, "--output (-o) FILENAME\n Optional output file.\n\n");
    fprintf(stream, "--help (-h)\n Print this information and discard other arguments.\n");
    fprintf(stream, "+---------------------------------------------------+\n");
}

int arg_ports(char const *arg, int *p_start, int *p_end) {
    char *p_hyph;

    if (*p_start != 0) {
        fprintf(stderr, "portscan: %s: Multiple ports/ranges of ports supplied in command.\n", arg);
        exit(1);
    }

    *p_start = strtol(arg, &p_hyph, 0);
    if (*p_start < 1 || *p_start > 65535) {
        fprintf(stderr, "portscan: Start port (%d) must be an integer between 1 and 65535.\n", *p_start);
        exit(1);
    }

    if (*p_hyph == '\0') {
        *p_end = *p_start;
        return 0;
    } else if (*p_hyph != '-') {
        fprintf(stderr, "portscan: %c: Syntax error.\n", *p_hyph);
        print_usage(stderr);
        exit(1);
    }
    
    *p_end = strtol(p_hyph + 1, &p_hyph, 0);
    if (*p_end < *p_start || *p_end > 65535) {
        fprintf(stderr, "portscan: End port (%d) must be an integer between start port (%d) and 65535.\n", *p_end, *p_start);
        exit(1);
    }

    if (*p_hyph != '\0') {
        fprintf(stderr, "portscan: %c: Syntax error.\n", *p_hyph);
        print_usage(stderr);
        exit(1);
    }
    
    return 0;
}

int parse_args(int argc, char const *argv[], char **dest, int *p_start, int *p_end, char **ifilename, char **ofilename) {
    int i;

    *p_start = *p_end = 0;
    *dest = *ifilename = *ofilename = NULL;

    // help
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            print_usage(stdout);
            exit(0);
        } 
    }

    for (i = 1; i < argc; i++) {

        // too few/many args
        if(i + 1 >= argc) {
            fprintf(stderr, "portscan: %s: Syntax error.\n", argv[i]);
            print_usage(stderr);
            exit(1);
        }

        // ports
        else if (!strcmp(argv[i], "--ports") || !strcmp(argv[i], "-p")) {
            arg_ports(argv[++i], p_start, p_end);
        }

        // ip
        else if (!strcmp(argv[i], "--ip") || !strcmp(argv[i], "-i")) {
            if (*dest != NULL) {
                fprintf(stderr, "portscan: %s: More than one IP address specified.\n", argv[i+1]);
                print_usage(stderr);
                exit(1);
            }
            if (!strcmp(argv[i+1], "localhost")) {
                *dest = strdup("127.0.0.1");
                i++;
            } else {
                *dest = strdup(argv[++i]);
            }
            
            if (*dest == NULL) {
                fprintf(stderr, "portscan: %s: %s\n", argv[i], strerror(errno));
            }
        }

        // input
        else if (!strcmp(argv[i], "--input") || !strcmp(argv[i], "--list") || !strcmp(argv[i], "-l")) {
            if (*ifilename != NULL) {
                fprintf(stderr, "portscan: %s: More than one input file supplied.\n", argv[i+1]);
                print_usage(stderr);
                exit(1);
            }
            if ((*ifilename = strdup(argv[++i])) == NULL) {
                fprintf(stderr, "portscan: %s: %s\n", argv[i], strerror(errno));
            }
        }

        // output
        else if (!strcmp(argv[i], "--output") || !strcmp(argv[i], "-o")) {
            if (*ofilename != NULL) {
                fprintf(stderr, "portscan: %s: More than one output file supplied.\n", argv[i+1]);
                print_usage(stderr);
                exit(1);
            }
            if ((*ofilename = strdup(argv[++i])) == NULL) {
                fprintf(stderr, "portscan: %s: %s\n", argv[i], strerror(errno));
            }
        }

        // unrecognised
        else {
            fprintf(stderr, "portscan: %s: Unrecognised argument.\n", argv[i]);
            print_usage(stderr);
            exit(1);
        }
    }
    return 0;
}

void check_args(char **dest, int *p_start, int *p_end, char **ifilename, char **ofilename, FILE **istream, int *ofd) {
    *ofd = -1;
    *istream = NULL;
    if (*ifilename != NULL) {
        if (*p_start != 0 || *dest != NULL) {
            fprintf(stderr, "portscan: Command-line arguments supplied despite input file.\n");
            print_usage(stderr);
            exit(1);
        }
        if ((*istream = fopen(*ifilename, "r")) == NULL) {
            fprintf(stderr, "portscan: %s: %s\n", *ifilename, strerror(errno));
            print_usage(stderr);
            exit(1);
        }
    } else { // set defaults
        if (*p_start == 0) {
            *p_start = 1;
            *p_end = 1024;
        }
        if (*dest == NULL) {
            if ((*dest = strdup("127.0.0.1")) == NULL) {
                fprintf(stderr, "portscan: %s\n", strerror(errno));
            }
        }
    }

    if (*ofilename != NULL && (*ofd = open(*ofilename, O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1) {
        fprintf(stderr, "portscan: %s: %s\n", *ofilename, strerror(errno));
        print_usage(stderr);
        exit(1);
    }
}

int parse_line(char **line, int n_line, char **dest, int *p_start, int *p_end, char **ifilename) {
    char *item, *endptr, delim[3];
    
    strcpy(delim, "\t\n");

    // IP Address
    item = strtok(*line, delim);
    if (item == NULL) {
        fprintf(stderr, "portscan: %s: %d: %s: Input file entries must adhere to the format specified below.\n",
            *ifilename, n_line, item);
        exit(1);
    }

    if (!strcmp(item, "localhost")) {
        *dest = strdup("127.0.0.1");
    } else {
        *dest = strdup(item);
    }

    if (*dest == NULL) {
        fprintf(stderr, "portscan: %s: %d: %s: %s\n",
            *ifilename, n_line, item, strerror(errno));
        exit(1);
    }

    // Port Start
    item = strtok(NULL, delim);
    if (item == NULL) {
        fprintf(stderr, "portscan: %s: %d: %s: Input file entries must adhere to the format specified below.\n",
            *ifilename, n_line, item);
        exit(1);
    }
    *p_start = strtol(item, &endptr, 0);
    if (*p_start < 1 || *p_start > 65535 || *endptr != '\0') {
        fprintf(stderr, "portscan: %s: %d: Start port (%d) must be an integer between 1 and 65535.\n",
            *ifilename, n_line, *p_start);
        exit(1);
    }

    // Port End
    item = strtok(NULL, delim);
    if (item == NULL) {
        fprintf(stderr, "portscan: %s: %d: %s: Input file entries must adhere to the format specified below.\n",
            *ifilename, n_line, item);
        exit(1);
    }
    *p_end = strtol(item, &endptr, 0);
    if (*p_end < *p_start || *p_end > 65535 || *endptr != '\0') {
        fprintf(stderr, "portscan: %s: %d: End port (%d) must be an integer between start port (%d) and 65535.\n",
            *ifilename, n_line, *p_end, *p_start);
        exit(1);
    }

    return 0;
}