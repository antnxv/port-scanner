#include "scanner.h"

int main(int argc, char const *argv[]) {
    FILE *istream;
    int p_max, ofd;
    struct sockaddr_in dest;
    char *ifilename, *ofilename, *line;
    
    parse_args(argc, argv, &p_max, &dest, &ifilename, &ofilename);
    check_args(&dest, &p_max, &ifilename, &ofilename, &istream, &ofd);

    if (ofd != -1) {
        dup2(ofd, 1);
    }
    
    if (istream != NULL) {
        line = NULL;
        while (getline(&line, NULL, istream)) {
            parse_line(&line, &dest, &p_max);


            // SCAN PORTS


            free(line);
        }
        free(line);
    } else {


        // SCAN PORTS


    }

    // debug
    printf("IP: %s\tPorts: %d-%d\tIn: %s\tOut: %s\n",
        inet_ntoa(dest.sin_addr), dest.sin_port, p_max, ifilename, ofilename);
    
    return 0;
}