all: portscan.o parse.o
	gcc -o portscan portscan.o parse.o

portscan.o: portscan.c portscan.h parse.h
	gcc -c portscan.c

parse.o: parse.c parse.h
	gcc -c parse.c

clean:
	rm -rf portscan *.o
