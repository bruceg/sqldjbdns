#include "buffer.h"
#include "dns.h"
#include "env.h"
#include "ip4.h"
#include "scan.h"
#include "stralloc.h"
#include "strerr.h"
#include "sqldns.h"

extern char* fatal;

extern void sql_exec(char* q);
extern unsigned sql_fetch(unsigned row, unsigned col, char** result);
extern unsigned sql_ntuples(void);

static int sql_fetch_ip4(unsigned row, unsigned col, char ip[4])
{
  char* data;
  unsigned length;

  if((length = sql_fetch(row, col, &data)) == SQLNULL || !length) return 0;
  return ip4_scan(data, ip) == length;
}

static int sql_fetch_ulong(unsigned row, unsigned col, unsigned long* result)
{
  char* data;
  unsigned length;

  if((length = sql_fetch(row, col, &data)) == SQLNULL || !length) return 0;
  return scan_ulong(data, result) == length;
}

static int sql_fetch_stralloc(unsigned row, unsigned col, stralloc* result)
{
  char* data;
  unsigned length;

  if((length = sql_fetch(row, col, &data)) == SQLNULL) return 0;
  if(!stralloc_copyb(result, data, length)) return 0;
  return stralloc_0(result);
}

static int stralloc_appendb(stralloc* s, char b)
{
  char tmp[1];
  tmp[0] = b;
  return stralloc_append(s, tmp);
}

static int stralloc_catoctal(stralloc* s, unsigned char c)
{
  char tmp[5];
  tmp[0] = '\\';
  tmp[1] = '0' + ((c >> 6) & 7);
  tmp[2] = '0' + ((c >> 3) & 7);
  tmp[3] = '0' + (c & 7);
  tmp[4] = 0;
  return stralloc_cats(s, tmp);
}

static int stralloc_cat_dns_to_sql(stralloc* s, char* name)
     /* Append the binary DNS name as text to the stralloc */
{
  int dot = 0;
  if(!stralloc_append(s, "'")) return 0;
  while(*name) {
    unsigned len;
    if(dot)
      if(!stralloc_append(s, ".")) return 0;
    for(len = *name++; len; --len, ++name) {
      char ch = *name;
      if(ch >= 'A' && ch <= 'Z') ch += 32;
      if((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
	 ch == '-' || ch == '_') {
	if(!stralloc_appendb(s, ch)) return 0;
      }
      else
	if(!stralloc_catoctal(s, ch)) return 0;
    }
    dot = 1;
  }
  return stralloc_append(s, "'");
}

static stralloc sql_query = {0,0,0};

static unsigned sql_select_entries(unsigned long domain)
{
  unsigned tuples;
  unsigned rtuples;
  unsigned i;
  sql_record* rec;
  
  if(!stralloc_copys(&sql_query,
		     "SELECT prefix,type,ttl,date_part('epoch',timestamp),"
		     "ip,distance,name "
		     "FROM entry "
		     "WHERE domain=")) return 0;
  if(!stralloc_catulong0(&sql_query, domain, 0)) return 0;
  if(!stralloc_0(&sql_query)) return 0;
  sql_exec(sql_query.s);

  tuples = sql_ntuples();
  if(!tuples) return 0;

  rec = sql_record_alloc(tuples);
  for(i = rtuples = 0; i < tuples; i++) {
    if(!sql_fetch_stralloc(i, 0, &rec->prefix)) continue;
    if(!sql_fetch_ulong(i, 1, &rec->type)) continue;
    if(!sql_fetch_ulong(i, 2, &rec->ttl)) rec->ttl = 0;
    if(!sql_fetch_ulong(i, 3, &rec->timestamp)) rec->timestamp = 0;
    
    switch(rec->type) {
    case DNS_NUM_A:
      if(!sql_fetch_ip4(i, 4, rec->ip)) continue;
      break;
    case DNS_NUM_MX:
      if(!sql_fetch_ulong(i, 5, &rec->distance)) continue;
      if(!sql_fetch_stralloc(i, 6, &rec->name)) continue;
      break;
    case DNS_NUM_TXT:
      if(!sql_fetch_stralloc(i, 6, &rec->name)) continue;
      break;
    default:
      continue;
    }
    ++rec;
    ++rtuples;
  }
  /* Return a single bogus record if no data was produced
   * but the prefix was found */
  if(!rtuples) {
    rec->type = 0;
    ++rtuples;
  }
  return rtuples;
}

int sql_select_domain(char* domain, stralloc* name)
{
  unsigned i;
  unsigned long id;

  if(!stralloc_copys(&sql_query,
		     "SELECT id,name "
		     "FROM domain "
		     "WHERE name="))
    return 0;
  for(i = 0; *domain; ++i, domain += *domain+1) {
    if(i)
      if(!stralloc_cats(&sql_query, " OR name=")) return 0;
    if(!stralloc_cat_dns_to_sql(&sql_query, domain)) return 0;
  }
  if(!stralloc_cats(&sql_query,
		    " ORDER BY length(name) DESC LIMIT 1"))
    return 0;
  if(!stralloc_0(&sql_query)) return 0;
  sql_exec(sql_query.s);
  if(sql_ntuples() != 1) return 0;
  if(!sql_fetch_ulong(0, 0, &id)) return 0;
  if(!sql_fetch_stralloc(0, 1, name)) return 0;
  if(name->len <= 1) return 0;
  sql_record_count = sql_select_entries(id);
  if(!sql_record_count) return 0;
  return 1;
}

unsigned sql_select_ip4(char ip[4])
{
  sql_record* rec;
  char ipstr[IP4_FMT];
  
  if(!stralloc_copys(&sql_query,
		     "SELECT prefix,name,ttl "
		     "FROM domain,entry "
		     "WHERE entry.domain=domain.id "
		     "AND type=1 "
		     "AND master_ip='T' "
		     "AND ip='")) return 0;
  if(!stralloc_catb(&sql_query, ipstr, ip4_fmt(ipstr, ip))) return 0;
  if(!stralloc_catb(&sql_query, "'", 2)) return 0;
  sql_exec(sql_query.s);
  if(!sql_ntuples()) return 1;

  rec = &sql_records[0];
  rec->type = DNS_NUM_PTR;
  if(!sql_fetch_stralloc(0, 0, &rec->prefix)) return 0;
  if(rec->prefix.len > 1) {
    if(!stralloc_copyb(&rec->name, rec->prefix.s, rec->prefix.len-1)) return 0;
  }
  else
    if(!stralloc_copys(&rec->name, "")) return 0;
  if(!sql_fetch_stralloc(0, 1, &sql_query)) return 0;
  if(!stralloc_cat(&rec->name, &sql_query)) return 0;
  if(!stralloc_0(&rec->name)) return 0;
  if(!sql_fetch_ulong(0, 2, &rec->ttl)) return 0;
  
  return 2;
}
