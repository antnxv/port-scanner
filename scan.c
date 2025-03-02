#include "scan.h"
#include "service.h"

int compare_ports(const void *a, const void *b) {
    return ((struct service *)a)->p - ((struct service *)b)->p;
}

int print_ports(int *start, int *prev, int curr) {
    struct service *known;

    struct service key = {curr, NULL};
    known = bsearch(&key, service_map, 752, sizeof(struct service), compare_ports);

    if (known || curr == 0 || (*prev != curr-1 && *start != 0)) {
        if (*prev != 0) {
            if (*start == *prev) {
                printf("  Port %d\n", *prev);
            } else {
                printf("  Ports %d-%d\n", *start, *prev);
            }
        }

        if (known) {
            printf("  Port %d (%s)\n", curr, known->service);
            return *start = *prev = 0;
        }

        *start = *prev = curr;
        return 0;
    }

    if (*start == 0) {
        *start = curr;
    }
    *prev = curr;
    return -1;
}

int print_error(long *port_status, int err) {
    switch (err) {
        case EALREADY:
            *port_status = 1;
            return 0;
        case ECONNREFUSED: case ETIMEDOUT: case ENETUNREACH:
            *port_status = 0;
            return 0;
        default:
            fprintf(stderr, "portscan: connect: %s\n", strerror(err));
            exit(1);
    }
}

long scan_port(char **dest, int p, int efd) {
    int s, info_status, port_status;
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

    if (connect(s, (struct sockaddr *) (&dp), sizeof (struct sockaddr)) == 0) {
        close(s);
        free(data);
        return 0;
    }

    if (epoll_ctl(efd, EPOLL_CTL_ADD, s, &e) == -1) {
        fprintf(stderr, "portscan: epoll_ctl: %s.\n", strerror(errno));
        close(s);
        free(data);
        exit(1);
    }
    return (long) e.data.ptr;
}

int scan_ports(char **dest, int *p_start, int *p_end) {
    int p_i, b, b_start, b_end, b_size;; // iterating through ports
    int p, efd, pfds, err, errlen; // processing connection results
    long s;
    int start, prev, curr; // printing open ports
    struct epoll_event erry[MAX_EVENTS];

    // stores data ptr if connection pending,
    // 0 if port closed, 1 if port open
    long ports[*p_end - *p_start + 1];

    memset(ports, 0, *p_end - *p_start + 1);
    
    if ((efd = epoll_create1(0)) == -1) {
        fprintf(stderr, "portscan: epoll_create1: %s.\n",
            strerror(errno));
        exit(1);
    }

    if (*p_start != *p_end) {
        printf("IP Address: %s\nStarting Port: %d\nEnd Port: %d\nOpen:\n",
            *dest, *p_start, *p_end);
    } else {
        printf("IP Address: %s\nPort: %d\nOpen port(s):\n",
            *dest, *p_start);
    }
    
    start = prev = 0;

    // Split ports up into MAX_EVENTS-sized batches
    for (b = 0; b < (*p_end - *p_start + MAX_EVENTS) / MAX_EVENTS; b++) {
        b_start = *p_start + b * MAX_EVENTS;
        b_end = (*p_end < b_start + MAX_EVENTS - 1)? *p_end : b_start + MAX_EVENTS - 1;
        b_size = b_end - b_start + 1;

        printf("Scanning %d-%d...", b_start, b_end);
        fflush(stdout);
        
        for (p_i = b_start; p_i <= b_end; p_i++) {
            if ((s = scan_port(dest, p_i, efd)) == 0) {
                ports[p_i - *p_start] = 1;
            } else {
                ports[p_i - *p_start] = s;
            }
        }

        while(b_size > 0) {
            if ((pfds = epoll_wait(efd, erry, MAX_EVENTS, TIMEOUT)) == -1) {
                fprintf(stderr, "portscan: epoll_wait: %s", strerror(errno));
                exit(1);
            }
            
            // timed out
            if (pfds == 0) {
                for (p_i = b_start; p_i <= b_end; p_i++) {
                    // unclosed socket, unfreed data
                    if (ports[p_i - *p_start] != 0 && ports[p_i - *p_start] != 1) {
                        close(((struct sp *) ports[p_i - *p_start])->s);
                        free((struct sp *) ports[p_i - *p_start]);
                    }
                }
                break;
            }
            
            b_size -= pfds;
            for (p_i = 0; p_i < pfds; p_i++) {
                s = ((struct sp *) erry[p_i].data.ptr)->s;
                p = ((struct sp *) erry[p_i].data.ptr)->p;
                
                errlen = sizeof err;
                
                if (getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &errlen) == -1) {
                    fprintf(stderr, "portscan: getsockopt: %s", strerror(errno));
                    exit(1);
                } else if (err == 0) {
                    ports[p - *p_start] = 1;
                } else {
                    print_error(ports + (p - *p_start), err);
                }

                free(erry[p_i].data.ptr);
                close(s);
            }
        }

        printf("\r                       \r");
        for (p_i = b_start; p_i <= b_end; p_i++) {
            if (ports[p_i - *p_start] == 1) {
                print_ports(&start, &prev, p_i);
            }
            print_ports(&start, &prev, 0); // force final print for batch
        }
    }

    close(efd);
    return 0;
}