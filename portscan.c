#include "portscan.h"

int main(int argc, char const *argv[]) {
    FILE *istream;
    size_t len;
    int p_start, p_end, ofd, n_line, split;
    char *dest, *ifilename, *ofilename, *line;
    
    parse_args(argc, argv, &dest, &p_start, &p_end, &ifilename, &ofilename);
    check_args(&dest, &p_start, &p_end, &ifilename, &ofilename, &istream, &ofd);

    if (ofd != -1) {
        dup2(ofd, 1);
    }
    
    if (istream != NULL) {
        line = NULL;
        n_line = 1;
        split = 0;
        while (getline(&line, &len, istream) != -1) {

            // allow splits to break up input files
            if (!strcmp(line, "\n")) {
                n_line++;
                continue;
            }

            if (n_line != 0)
            parse_line(&line, n_line, &dest, &p_start, &p_end, &ifilename);
            
            // separate outputs for separate list entries
            if (split) {
                printf("\n");
            } else {
                split = 1;
            }

            scan_ports(&dest, &p_start, &p_end);

            free(line);
            n_line++;
        }
    } else {
        scan_ports(&dest, &p_start, &p_end);
    }
    
    exit(0);
}