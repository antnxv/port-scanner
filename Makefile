GNUFLAG = -D_GNU_SOURCE

all: portscan.o scan.o parse.o
	gcc -o portscan portscan.o scan.o parse.o

portscan.o: portscan.c portscan.h parse.h
	gcc -c portscan.c

scan.o: scan.c scan.h parse.h service.h
	gcc $(GNUFLAG) -c scan.c

parse.o: parse.c parse.h
	gcc -c parse.c

clean:
	rm -rf portscan *.o
