default: pgsqldns

patch:
	cd djbdns-1.02 && rm -fv `cat TARGETS` *.orig *~
	diff -urN djbdns-1.02-orig djbdns-1.02 | \
	grep -v '^Binary files .* differ$$' >diff

pgsqldns: pgsqldns.o sqldns.o
	cd djbdns-1.02 && ./load ../pgsqldns ../sqldns.o server.o \
		response.o droproot.o qlog.o prot.o dd.o dns.a env.a \
		cdb.a alloc.a buffer.a unix.a byte.a  `cat socket.lib` -lpq
	size pgsqldns

sqldns.o: sqldns.c sql.h
	gcc -O2 -W -Wall -Idjbdns-1.02 -c sqldns.c

pgsqldns.o: pgsqldns.c sql.h
	gcc -O2 -W -Wall -Idjbdns-1.02 -c pgsqldns.c

clean:
	$(RM) *.o pgsqldns
