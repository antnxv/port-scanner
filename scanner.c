#include "scanner.h"

int main(int argc, char const *argv[]) {
    int p_max, ifd, ofd;
    struct sockaddr_in dest;
    char *ifilename, *ofilename;
    
    parse_args(argc, argv, &p_max, &dest, &ifilename, &ofilename);
    check_args(&dest, &p_max, &ifilename, &ofilename, &ifd, &ofd);
    
    // dup2(ofd, 1); // write all output to ofilename
    
    // debug
    printf("IP: %s\tPorts: %d-%d\tIn: %s\tOut: %s\n",
        inet_ntoa(dest.sin_addr), dest.sin_port, p_max, ifilename, ofilename);
    
    return 0;
}