#include <pwd.h>
#include "djbdns/strerr.h"
#include "djbdns/exit.h"
#include "djbdns/auto_home.h"
#include "djbdns/generic-conf.h"

#define FATAL "pgsqldns-conf: fatal: "

void usage(void)
{
  strerr_die1x(100,"pgsqldns-conf: usage: pgsqldns-conf acct logacct /pgsqldns myip");
}

char *dir;
char *user;
char *loguser;
struct passwd *pw;
char *myip;

int main(int argc, char **argv)
{
  user = argv[1];
  if (!user) usage();
  loguser = argv[2];
  if (!loguser) usage();
  dir = argv[3];
  if (!dir) usage();
  if (dir[0] != '/') usage();
  myip = argv[4];
  if (!myip) usage();

  pw = getpwnam(loguser);
  if (!pw)
    strerr_die3x(111,FATAL,"unknown account ",loguser);

  init(dir,FATAL);
  makelog(loguser,pw->pw_uid,pw->pw_gid);

  makedir("env");
  perm(02755);
  start("env/ROOT"); outs(dir); outs("/root\n"); finish();
  perm(0644);
  start("env/IP"); outs(myip); outs("\n"); finish();
  perm(0644);

  start("run");
  outs("#!/bin/sh\n"
       "exec 2>&1\n"
       "rm -f root/tmp/.s.PGSQL.*\n"
       "ln /tmp/.s.PGSQL.* root/tmp\n"
       "exec envuidgid "); outs(user);
  outs(" envdir ./env softlimit -d2000000 ");
  outs(auto_home); outs("/bin/pgsqldns\n");
  finish();
  perm(0755);

  makedir("root");
  perm(02755);

  makedir("root/tmp");
  perm(0755);
  
  _exit(0);
}
