#include "buffer.h"
#include "ip4.h"
#include "scan.h"
#include "stralloc.h"
#include "strerr.h"
#include <pgsql/libpq-fe.h>
#include "sqldns.h"

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

int sql_fetch_ip4(unsigned row, unsigned col, char ip[4])
{
  char* data;
  unsigned length;

  length = sql_fetch(row, col, &data);
  return length > 0 && ip4_scan(data, ip) == length;
}

int sql_fetch_ulong(unsigned row, unsigned col, unsigned long* result)
{
  char* data;
  unsigned length;

  length = sql_fetch(row, col, &data);
  return length > 0 && scan_ulong(data, result) == length;
}

static int name_to_dns(stralloc* dns, char* name)
     /* Convert the given text domain name into DNS binary format. */
{
  if(!stralloc_copys(dns, "")) return 0;
  while(*name == '.')
    ++name;
  while(*name) {
    char* start = name;
    unsigned char tmp[1];
    while(*name && *name != '.')
      ++name;
    tmp[0] = name - start;
    if(!stralloc_catb(dns, tmp, 1)) return 0;
    if(!stralloc_catb(dns, start, tmp[0])) return 0;
    while(*name == '.')
      ++name;
  }
  if(!stralloc_0(dns)) return 0;
  return 1;
}

static int sql_fetch_stralloc(unsigned row, unsigned col, stralloc* result)
{
  char* data;
  unsigned length;

  length = sql_fetch(row, col, &data);
  if(!length) return 0;
  if(!name_to_dns(result, data)) return 0;
  return 1;
}

int stralloc_cat_dns_to_sql(stralloc* s, char* name)
     /* Append the binary DNS name as text to the stralloc */
{
  int dot = 0;
  while(*name) {
    unsigned len = *name++;
    if(dot)
      if(!stralloc_append(s, ".")) return 0;
    if(!stralloc_catb(s, name, len)) return 0;
    name += len;
    dot = 1;
  }
  return 1;
}

int stralloc_catb_dns_to_sql(stralloc* s, char* name, int bytes)
     /* Append a limited number of bytes of the binary DNS name as
        text to the stralloc */
{
  int dot = 0;
  while(bytes > 0 && *name) {
    unsigned len = *name++;
    if(dot)
      if(!stralloc_append(s, ".")) return 0;
    if(!stralloc_catb(s, name, len)) return 0;
    name += len;
    bytes -= len + 1;
    dot = 1;
  }
  return 1;
}

static stralloc sql_query = {0,0,0};

int sql_select_domain(char* domain, unsigned long* id, char** name)
{
  unsigned i;
  
  if(!stralloc_copys(&sql_query,
		     "SELECT id,name "
		     "FROM domain "
		     "WHERE name='"))
    return 0;
  for(i = 0; *domain; ++i, domain += *domain+1) {
    if(i)
      if(!stralloc_cats(&sql_query, " OR name='")) return 0;
    if(!stralloc_cat_dns_to_sql(&sql_query, domain)) return 0;
    if(!stralloc_append(&sql_query, "'")) return 0;
  }
  if(!stralloc_cats(&sql_query,
		    " ORDER BY length(name) DESC LIMIT 1"))
    return 0;
  if(!stralloc_0(&sql_query)) return 0;
  sql_exec(sql_query.s);
  if(sql_ntuples() != 1) return 0;
  if(!sql_fetch_ulong(0, 0, id)) return 0;
  if(!sql_fetch(0, 1, name)) return 0;
  return 1;
}

unsigned sql_select_entries(unsigned long domain, char* prefix,
			    int lookup_A, int lookup_MX)
{
  unsigned tuples;
  unsigned rtuples;
  unsigned i;
  sql_record* rec;
  
  if(!stralloc_copys(&sql_query, "SELECT ttl")) return 0;
  if(lookup_A && !stralloc_cats(&sql_query, ",ip")) return 0;
  if(lookup_MX && !stralloc_cats(&sql_query, ",mx_name1,mx_name2")) return 0;
  if(!stralloc_cats(&sql_query, " FROM entry WHERE domain=")) return 0;
  if(!stralloc_catulong0(&sql_query, domain, 0)) return 0;
  if(!stralloc_cats(&sql_query, " AND prefix='")) return 0;
  if(!stralloc_cat_dns_to_sql(&sql_query, prefix)) return 0;
  if(!stralloc_append(&sql_query, "'")) return 0;
  if(!stralloc_0(&sql_query)) return 0;
  sql_exec(sql_query.s);

  tuples = sql_ntuples();
  if(!tuples) return 0;

  rec = sql_records;
  for(i = rtuples = 0; i < tuples; i++) {
    unsigned field = 1;
    
    if(!sql_fetch_ulong(i, 0, &rec->ttl)) continue;
    if(lookup_A && sql_fetch_ip4(i, field++, rec->ip)) {
      rec->type = DNS_NUM_A;
      ++rec;
      if(++rtuples > SQL_RECORD_MAX) break;
    }
    if(lookup_MX && sql_fetch_stralloc(i, field++, &rec->name)) {
      rec->type = DNS_NUM_MX;
      rec->distance = 1;
      ++rec;
      if(++rtuples > SQL_RECORD_MAX) break;
    }
    if(lookup_MX && sql_fetch_stralloc(i, field++, &rec->name)) {
      rec->type = DNS_NUM_MX;
      rec->distance = 2;
      ++rec;
      if(++rtuples > SQL_RECORD_MAX) break;
    }
  }
  return rtuples;
}

