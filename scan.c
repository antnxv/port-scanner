#include "scan.h"

int print_ports(int *start, int *prev, int curr) {
    if (/* curr ~ KNOWN SERVICE || */ (curr != *prev - 1 && *start != 0) || (curr == 0 && *prev != 0)) {
        if (*start == *prev) {
            printf("  Port %d\n", *prev);
        } else  {
            printf("  Ports %d-%d\n", *start, *prev);
        }
        /* if ( curr ~ KNOWN SERVICE) {
            printf("Port %d (%s)\n", curr, "SERVICE");
        } */
        *start = curr;
        *prev = curr;
        return 0;
    }

    if (*start == 0) {
        *start = curr;
    }
    *prev = curr;
    return -1;
}

int print_error(char *port_status, int err) {
    // report network errors,
    // fail on system/process errors
    switch (err) {
        case EALREADY:
            *port_status = 1;
        case ECONNREFUSED: case ETIMEDOUT: case ENETUNREACH:
            return 0;
        default:
            fprintf(stderr, "portscan: connect: %s\n", strerror(err));
            exit(1);
    }
}

int scan_port(char **dest, int p, int efd) {
    int s, info_status, port_status;
    struct timeval t;
    struct sp *data;
    struct sockaddr_in dp;
    struct epoll_event e;

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

    data = malloc(sizeof(struct sp));
    data->s = s;
    data->p = p;
    e.data.ptr = data;
    e.events = EPOLLOUT;
    fcntl(s, F_SETFL, O_NONBLOCK);

    t.tv_sec = TIMEOUT;
    t.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &t, sizeof t);

    if (connect(s, (struct sockaddr *) (&dp), sizeof (struct sockaddr)) == 0) {
        free(data);
        close(s);
        return 0;
    }

    if (epoll_ctl(efd, EPOLL_CTL_ADD, s, &e) == -1) {
        fprintf(stderr, "portscan: epoll_ctl: %s.\n",
            strerror(errno));
        free(data);
        close(s);
        exit(1);
    }
    return s;
}

int scan_ports(char **dest, int *p_start, int *p_end) {
    int p_i, b, b_start, b_end;; // iterating through ports
    int s, p, efd, pfds, err, errlen; // processing connection results
    int start, prev, curr; // printing open ports
    struct epoll_event erry[MAX_EVENTS];

    // initially stores socket fds, then stores 1 for open, 0 for closed
    char ports[*p_end - *p_start + 1];

    memset(ports, 0, *p_end - *p_start + 1);
    
    if ((efd = epoll_create1(0)) == -1) {
        fprintf(stderr, "portscan: epoll_create1: %s.\n",
            strerror(errno));
        exit(1);
    }

    if (*p_start != *p_end) {
        printf("IP Address: %s\nStarting Port: %d\nEnd Port: %d\nOpen port(s):\n",
            *dest, *p_start, *p_end);
    } else {
        printf("IP Address: %s\nPort: %d\nOpen port(s):\n",
            *dest, *p_start);
    }
    
    // Split ports up into MAX_EVENTS-sized batches
    for (b = 0; b < (*p_end - *p_start + MAX_EVENTS) / MAX_EVENTS; b++) {
        b_start = *p_start + b * MAX_EVENTS;
        b_end = b_start + MAX_EVENTS - 1;
        for (p_i = b_start; p_i <= *p_end && p_i <= b_end; p_i++) {
            if ((s = scan_port(dest, p_i, efd)) == 0) {
                ports[p_i - *p_start] = 1;
            } else {
                ports[p_i - *p_start] = s;
            }
        }
        
        pfds = epoll_wait(efd, erry, MAX_EVENTS, -1);
        // handle errno or pfds not being every event

        for (p_i = 0; p_i < pfds; p_i++) {
            s = ((struct sp *) erry[p_i].data.ptr)->s;
            p = ((struct sp *) erry[p_i].data.ptr)->p;
            
            errlen = sizeof err;
            getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &errlen);
            if (err == 0) {
                ports[p - *p_start] = 1;
                printf("%d - %d = %d\n", p, *p_start, p - *p_start);
            } else {
                print_error(ports + (p - *p_start), err);
            }

            free(erry[p_i].data.ptr);
            close(s);
        }

        start = prev = 0;
        for (p_i = b_start; p_i <= *p_end && p_i <= b_end; p_i++) {
            if (ports[p_i - *p_start] == 1) {
                print_ports(&start, &prev, p_i);
            }
        }
    }

    print_ports(&start, &prev, 0); // force final print

    close(efd);
    return 0;
}