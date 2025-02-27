#include "scan.h"

int print_ports(int *start, int *prev, int curr) {
    if (/* curr ~ KNOWN SERVICE || */ (curr != *prev - 1 && *start != 0)) {
        if (*start == *prev) {
            printf("  Port %d\n", *prev);
        } else {
            printf("  Ports %d-%d\n", *start, *prev);
        }
        /* if ( curr ~ KNOWN SERVICE) {
            printf("Port %d (%s)\n", curr, "SERVICE");
        } */
        *start = 0;
        *prev = 0;
        return 0;
    }

    if (*start == 0) {
        *start = curr;
    }
    *prev = curr;
    return -1;
}

int print_error(int *port_status) {
    // report network errors,
    // fail on system/process errors
    switch (errno) {
        case EALREADY:
            *port_status = 0;
        case ECONNREFUSED: case ETIMEDOUT: case ENETUNREACH:
            return 0;
        default:
            fprintf(stderr, "portscan: connect: %s\n", strerror(errno));
            return -1;
    }
}

int scan_ports(char **dest, int *p_start, int *p_end) {
    int i, port_status, start, prev, curr;
    
    if (*p_start != *p_end) {
        printf("IP Address: %s\nStarting Port: %d\nEnd Port: %d\nOpen port(s):\n",
            *dest, *p_start, *p_end);
    } else {
        printf("IP Address: %s\nPort: %d\nOpen port(s):\n",
            *dest, *p_start);
    }
    
    start = prev = 0;
    for (i = *p_start; i <= *p_end; i++) {
        port_status = scan_port(dest, i);
        if (port_status == 0) {
            print_ports(&start, &prev, i);
        }
        prev = i;
    }
    print_ports(&start, &prev, 0); // force final print
    return 0;
}

int scan_port(char **dest, int p) {
    int s, info_status, port_status;
    struct sockaddr_in dp;

    dp.sin_port = htons(p);
    dp.sin_family = AF_INET;
    if (inet_aton(*dest, &(dp.sin_addr)) == 0) {
        fprintf(stderr, "portscan: %s: Invalid address. Use IPv4 numbers-and-dots notation.\n",
            *dest);
        exit(1);
    }

    if ((s = socket(dp.sin_family, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "portscan: socket: %s\n", strerror(errno));
        exit(1);
    }

    // if (fcntl(s, F_SETFL, O_NONBLOCK) == -1) {
    //     fprintf(stderr, "portscan: fcntl: %s\n", strerror(errno));
    //     exit(1);
    // }

    if ((port_status = connect(s, (struct sockaddr *) (&dp), sizeof (struct sockaddr))) != 0
    && errno != EINPROGRESS) {
        close(s);
        if (print_error(&port_status) == -1) {
            exit(1);
        }
    }

    // handle nonblocking

    return port_status;
}