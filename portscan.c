#include "portscan.h"

int main(int argc, char const *argv[]) {
    FILE *istream;
    size_t len;
    int p_start, p_end, ofd, n_line;
    char *dest, *ifilename, *ofilename, *line;
    
    parse_args(argc, argv, &dest, &p_start, &p_end, &ifilename, &ofilename);
    check_args(&dest, &p_start, &p_end, &ifilename, &ofilename, &istream, &ofd);

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

            parse_line(&line, n_line, &dest, &p_start, &p_end, &ifilename);
            scan_ports(&dest, &p_start, &p_end);

            free(line);
            n_line++;
        }
        printf("total lines %d\n", n_line-1);
    } else {
        scan_ports(&dest, &p_start, &p_end);
    }
    
    free(dest);
    free(ifilename);
    free(ofilename);
    return 0;
}