PACKAGE = sqldjbdns
VERSION = 0.70

djbdns = djbdns-1.02

CC = gcc
CFLAGS = -O2 -W -Wall -I$(djbdns) -g -DSQL_LOG
install = /usr/bin/install

install_prefix =
prefix = /usr
bindir = $(install_prefix)$(prefix)/bin

PROGS = pgsqldns pgsqldns-conf dnsbench

default: $(PROGS)

pgsqldns: pgsqldns.o sqldns.o sqlrecord.o sqlschema.o $(djbdns)/dns.a
	cd $(djbdns) && ./load ../pgsqldns ../sqldns.o ../sqlschema.o \
		../sqlrecord.o server.o response.o droproot.o qlog.o \
		prot.o dd.o dns.a env.a cdb.a alloc.a buffer.a \
		unix.a byte.a libtai.a `cat socket.lib` -lpq

pgsqldns-conf: pgsqldns-conf.o $(djbdns)/dns.a
	cd $(djbdns) && ./load ../pgsqldns-conf generic-conf.o \
		auto_home.o buffer.a byte.a unix.a

dnsbench: dnsbench.o $(djbdns)/dns.a
	cd $(djbdns) && ./load ../dnsbench dns.a env.a \
		alloc.a unix.a byte.a iopause.o \
		libtai.a `cat socket.lib`

install: $(PROGS)
	$(install) -d $(bindir)
	$(install) $(PROGS) $(bindir)

dnsbench.o: dnsbench.c Makefile
pgsqldns.o: pgsqldns.c sqldns.h $(djbdns)/uint32.h Makefile
pgsqldns-conf.o: pgsqldns-conf.c $(djbdns)/uint32.h Makefile
sqldns.o: sqldns.c sqldns.h $(djbdns)/uint32.h Makefile
sqlrecord.o: sqlrecord.c sqldns.h $(djbdns)/uint32.h Makefile
sqlschema.o: sqlschema.c sqldns.h $(djbdns)/uint32.h Makefile

$(djbdns)/dns.a: $(djbdns)/dns_domain.c
	$(MAKE) -C $(djbdns)

$(djbdns)/uint32.h: $(djbdns)/tryulong32.c
	$(MAKE) -C $(djbdns)

clean:
	$(RM) *.o $(PROGS)
