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

%description
Sqldjbdns is an authoritative DNS server that pulls its data directly
from a set of SQL tables.

%package pgsql
Summary: PostgreSQL based sqldns server
Group: Networking/Daemons
Requires: postgresql
%description pgsql
Pgsqldns is an authoritative DNS server that pulls its data directly
from a set of PostgreSQL tables.

%prep
%setup
gzip -dc %{SOURCE1} | tar -xf -

%build
make

%install
rm -fr $RPM_BUILD_ROOT
make install_prefix=$RPM_BUILD_ROOT install

%clean
rm -rf $RPM_BUILD_ROOT

%files pgsql
%defattr(-,root,root)
%doc ANNOUNCEMENT NEWS README STATUS TODO *.html
/usr/bin/pgsqldns*
