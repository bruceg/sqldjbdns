#include "buffer.h"
#include "stralloc.h"
#include "strerr.h"
#include <pgsql/libpq-fe.h>
#include "sql.h"

extern char* fatal;

static PGconn* pgsql;
static PGresult* sql_result = 0;

void sql_exec(char* q)
{
#if 0
  buffer_puts(buffer_1, q);
  buffer_putsflush(buffer_1, "\n");
#endif
  if(sql_result)
    PQclear(sql_result);
  sql_result = PQexec(pgsql, q);
}

void sql_connect(void)
{
  pgsql = PQconnectdb("");
  /* Check  to see that the backend connection was successfully made */
  if (PQstatus(pgsql) == CONNECTION_BAD)
    strerr_die3x(111,fatal,"Could not connect to database: ",
		 PQerrorMessage(pgsql));
}

unsigned sql_fetch(unsigned row, unsigned col, char** result)
{
  int length = PQgetlength(sql_result, row, col);
  if(length <= 0)
    return 0;
  *result = PQgetvalue(sql_result, row, col);
  return length;
}

unsigned sql_ntuples(void)
{
  return PQntuples(sql_result);
}
