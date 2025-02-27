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

int scan_ports(char **dest, int *p_start, int *p_end) {
    int i, port_status, start, prev, curr;
    
    printf("IP Address: %s\nStarting Port: %d\nEnd Port: %d\nOpen port(s):\n",
        *dest, *p_start, *p_end);
    
    for (i = *p_start; i <= *p_end; i++) {
        port_status = scan_port(dest, i);
        if (port_status == 0) {
            print_ports(&start, &prev, i);
        }
        prev = i;
    }
    printf("\n");
    return 0;
}

int scan_port(char **dest, int p) {
    int s, info_status, port_status;
    struct addrinfo *rp;

    if (info_status = getaddrinfo(*dest, NULL, NULL, &rp)) {
        fprintf(stderr, "portscan: %s: %s\n", *dest, strerror(errno));
        exit(1);
    }

    rp->ai_family = AF_INET;
    rp->ai_socktype = SOCK_STREAM;
    if ((s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) == -1) {
        fprintf(stderr, "[1]portscan: %s\n", strerror(errno));
        exit(1);
    }

    // report network errors,
    // fail on system/process errors
    if ((port_status = connect(s, rp->ai_addr, rp->ai_addrlen)) == -1) {
        
        if (errno == EINPROGRESS) {
            // socket is nonblocking and the connection may not have
            // completed. currently unhandled.
            // while unhandled, the entire program cannot work, so we
            // fail out of the port scanner with the switch below.
        }

        
        fprintf(stderr, "portscan: %d: %s\n", errno, strerror(errno));
        switch (errno) {
            case EALREADY:
                // port is already in use, meaning open
                return 0;
            case ECONNREFUSED:
                break;
            case EPERM: case EACCES:
            case ETIMEDOUT: case ENETUNREACH:
                fprintf(stderr, "[3]portscan: %s\n", strerror(errno));
                break;
            default:
                fprintf(stderr, "[4]portscan: %s\n", strerror(errno));
                exit(1);
        }
    }

    close(s);
    return port_status;
}