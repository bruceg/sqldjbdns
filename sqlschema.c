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
  if(ip4_scan(data, ip) != length) return 0;
  return 1;
}

static int sql_fetch_ulong(unsigned row, unsigned col, unsigned long* result)
{
  char* data;
  unsigned length;

  if((length = sql_fetch(row, col, &data)) == SQLNULL || !length) return 0;
  if(scan_ulong(data, result) != length) return 0;
  return 1;
}

static int sql_fetch_stralloc(unsigned row, unsigned col, stralloc* result)
{
  char* data;
  unsigned length;

  if((length = sql_fetch(row, col, &data)) == SQLNULL) return 0;
  if(!name_to_dns(result, data)) return 0;
  return 1;
}

static int stralloc_cat_dns_to_sql(stralloc* s, char* name)
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

static stralloc sql_query = {0,0,0};

int sql_select_domain(char* domain, unsigned long* id, stralloc* name)
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
  if(!sql_fetch_stralloc(0, 1, name)) return 0;
  if(name->len <= 1) return 0;
  return 1;
}

static int stralloc_cat_prefixes(stralloc* q, stralloc* prefixes)
{
  char* ptr;
  unsigned len;
  int first;
  unsigned left;
  
  ptr = prefixes->s;
  left = prefixes->len;
  first = 1;

  while(left) {
    if(!first && !stralloc_cats(q, " OR ")) return 0;
    if(!stralloc_cats(q, "prefix='")) return 0;
    if(!stralloc_cat_dns_to_sql(q, ptr)) return 0;
    if(!stralloc_append(q, "'")) return 0;
    len = dns_domain_length(ptr);
    ptr += len;
    left -= len;
  }
  return 1;
}

static stralloc scratch;

unsigned sql_select_entries(unsigned long domain, stralloc* prefixes)
{
  unsigned tuples;
  unsigned rtuples;
  unsigned i;
  sql_record* rec;
  
  if(!prefixes->len) return 0;

  if(!stralloc_copys(&sql_query,
		     "SELECT prefix,ttl,ip,mx_name1,mx_name2")) return 0;
  if(!stralloc_cats(&sql_query, " FROM entry WHERE domain=")) return 0;
  if(!stralloc_catulong0(&sql_query, domain, 0)) return 0;
  if(!stralloc_cats(&sql_query, " AND (")) return 0;
  if(!stralloc_cat_prefixes(&sql_query, prefixes)) return 0;
  if(!stralloc_append(&sql_query, ")")) return 0;
  if(!stralloc_0(&sql_query)) return 0;
  sql_exec(sql_query.s);

  tuples = sql_ntuples();
  if(!tuples) return 0;

  rec = sql_records;
  for(i = rtuples = 0; i < tuples; i++) {
    unsigned long ttl;
    
    if(!sql_fetch_stralloc(i, 0, &scratch)) return 0;
    if(!sql_fetch_ulong(i, 1, &ttl)) continue;
    
    if(sql_fetch_ip4(i, 2, rec->ip)) {
      if(!stralloc_copy(&rec->prefix, &scratch)) return 0;
      rec->type = DNS_NUM_A;
      rec->ttl = ttl;
      ++rec;
      if(++rtuples > SQL_RECORD_MAX) break;
    }
    if(sql_fetch_stralloc(i, 3, &rec->name)) {
      if(!stralloc_copy(&rec->prefix, &scratch)) return 0;
      rec->type = DNS_NUM_MX;
      rec->ttl = ttl;
      rec->distance = 1;
      ++rec;
      if(++rtuples > SQL_RECORD_MAX) break;
    }
    if(sql_fetch_stralloc(i, 4, &rec->name)) {
      if(!stralloc_copy(&rec->prefix, &scratch)) return 0;
      rec->type = DNS_NUM_MX;
      rec->ttl = ttl;
      rec->distance = 2;
      ++rec;
      if(++rtuples > SQL_RECORD_MAX) break;
    }
  }
  /* Return a single bogus record if no data was produced
   * but the prefix was found */
  if(!rtuples) {
    rec->type = 0;
    ++rtuples;
  }
  return rtuples;
}

unsigned sql_select_ip4(char ip[4])
{
  sql_record* rec;
  char ipstr[IP4_FMT];
  
  if(!stralloc_copys(&sql_query,
		     "SELECT prefix,name,ttl "
		     "FROM domain,entry "
		     "WHERE entry.domain=domain.id "
		     "AND master_ip='T' and ip='")) return 0;
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
