CC = gcc
CFLAGS = -O4 -W -Wall -Idjbdns-1.02 -g

PROGS = pgsqldns dnsbench

default: $(PROGS)

patch:
	cd djbdns-1.02 && rm -fv `cat TARGETS` *.orig *~
	diff -urN djbdns-1.02-orig djbdns-1.02 | \
	grep -v '^Binary files .* differ$$' >diff

pgsqldns: pgsqldns.o sqldns.o
	cd djbdns-1.02 && ./load ../pgsqldns ../sqldns.o server.o \
		response.o droproot.o qlog.o prot.o dd.o dns.a env.a \
		cdb.a alloc.a buffer.a unix.a byte.a  `cat socket.lib` -lpq
	size pgsqldns

dnsbench: dnsbench.o
	cd djbdns-1.02 && ./load ../dnsbench dns.a env.a \
		alloc.a unix.a byte.a iopause.o \
		libtai.a `cat socket.lib`

sqldns.o: sqldns.c sqldns.h Makefile
pgsqldns.o: pgsqldns.c sqldns.h Makefile
dnsbench.o: dnsbench.c Makefile

clean:
	$(RM) *.o $(PROGS)
