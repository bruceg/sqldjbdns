#include "buffer.h"
#include "dns.h"
#include "env.h"
#include "ip4.h"
#include "scan.h"
#include "stralloc.h"
#include "strerr.h"
#include <pgsql/libpq-fe.h>
#include "sqldns.h"

extern char* fatal;

static PGconn* pgsql;
static PGresult* sql_result = 0;

#ifdef SQL_LOG
#include <stdio.h>
#endif

void sql_exec(char* q)
{
  ExecStatusType status;
#ifdef SQL_LOG
  PQprintOpt opt = { 1, 1, 0, 0, 0, 0, "|", 0, 0, 0 };
  buffer_puts(buffer_1, q);
  buffer_putsflush(buffer_1, "\n");
#endif
  if(sql_result)
    PQclear(sql_result);
  sql_result = PQexec(pgsql, q);
  status = PQresultStatus(sql_result);
  if(status != PGRES_TUPLES_OK && status != PGRES_COMMAND_OK)
    strerr_die3x(111,fatal,"Fatal PostgreSQL error: ",
		 PQresultErrorMessage(sql_result));
#ifdef SQL_LOG
  if(status == PGRES_TUPLES_OK) {
    PQprint(stdout, sql_result, &opt);
    fflush(stdout);
  }
#endif
}

void sql_connect(void)
{
  char* env;
  
  pgsql = PQconnectdb("");
  /* Check  to see that the backend connection was successfully made */
  if (PQstatus(pgsql) == CONNECTION_BAD)
    strerr_die3x(111,fatal,"Could not connect to database: ",
		 PQerrorMessage(pgsql));

  env = env_get("SQL_INITIALIZE");
  if(env)
    sql_exec(env);
}

unsigned sql_fetch(unsigned row, unsigned col, char** result)
{
  int length;
  if(PQgetisnull(sql_result, row, col)) return SQLNULL;
  if((length = PQgetlength(sql_result, row, col)) <= 0) return 0;
  *result = PQgetvalue(sql_result, row, col);
  return length;
}

unsigned sql_ntuples(void)
{
  return PQntuples(sql_result);
}
