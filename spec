Name: sqldjbdns
Summary: SQL DNS server based on djbdns
Version: @VERSION@
Release: 1
Copyright: GPL
Group: Networking/Daemons
Source0: http://em.ca/~bruceg/sqldjbdns/%{version}/sqldjbdns-%{version}.tar.gz
Source1: http://cr.yp.to/djbdns/djbdns-1.02.tar.gz
BuildRoot: /tmp/sqldjbdns-root
URL: http://em.ca/~bruceg/sqldjbdns/
Packager: Bruce Guenter <bruceg@em.ca>
Conflicts: bind
Requires: postgresql

%description
Sqldjbdns is a new authoritative DNS server that pulls its data directly
from a set of SQL tables.

%prep
%setup

%build
make

%install
rm -fr $RPM_BUILD_ROOT
make install_prefix=$RPM_BUILD_ROOT install

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc README STATUS TODO *.html
/usr/bin/pgsqldns
