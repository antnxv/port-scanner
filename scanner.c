#include "scanner.h"

int main(int argc, char const *argv[]) {
    FILE *istream;
    size_t len;
    int p_max, ofd, n_line;
    struct sockaddr_in dest;
    char *ifilename, *ofilename, *line;
    
    parse_args(argc, argv, &p_max, &dest, &ifilename, &ofilename);
    check_args(&dest, &p_max, &ifilename, &ofilename, &istream, &ofd);

    if (ofd != -1) {
        dup2(ofd, 1);
    }
    
    if (istream != NULL) {
        line = NULL;
        n_line = 1;
        while (getline(&line, &len, istream) != -1) {

            // allow newlines to break up input files
            if (!strcmp(line, "\n")) {
                continue;
            }

            parse_line(&line, n_line, &dest, &p_max, &ifilename);

            // debug
            printf("IP: %s\tPorts: %d-%d\tIn: %s\tOut: %s\n",
                inet_ntoa(dest.sin_addr), dest.sin_port, p_max, ifilename, ofilename);


            // SCAN PORTS


            free(line);
            n_line++;
        }
        printf("total lines %d\n", n_line-1);
    } else {
        // debug
        printf("IP: %s\tPorts: %d-%d\tIn: %s\tOut: %s\n",
            inet_ntoa(dest.sin_addr), dest.sin_port, p_max, ifilename, ofilename);


        // SCAN PORTS


    }
    
    free(ifilename);
    free(ofilename);
    return 0;
}