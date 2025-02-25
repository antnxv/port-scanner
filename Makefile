all: scanner.o scanner_io.o
	gcc -o portscan scanner.o scanner_io.o

scanner.o: scanner.c scanner.h scanner_io.h
	gcc -c scanner.c

scanner_io.o: scanner_io.c scanner_io.h
	gcc -c scanner_io.c

clean:
	rm -rf portscan *.o
