#include "djbdns/byte.h"
#include "djbdns/dns.h"
#include "djbdns/str.h"
#include "djbdns/strerr.h"
#include <stdlib.h>
#include "sqldns.h"

sql_record* sql_records = 0;
unsigned sql_record_size = 0;
unsigned sql_record_count = 0;

extern char *fatal;

sql_record* sql_record_alloc(unsigned size)
{
  if(size > sql_record_size) {
    sql_records = realloc(sql_records, size * sizeof(sql_record));
    if(!sql_records)
      strerr_die2x(111, fatal, "Could not allocate memory for record set");
    byte_zero(sql_records + sql_record_size*sizeof(sql_record),
	      (size - sql_record_size) * sizeof(sql_record));
    sql_record_size = size;
  }
  return sql_records;
}

/* The call to dns_random will cause the sorted data set to have like items
 * put into a randomized order */
static int cmp_records(const sql_record* a, const sql_record* b)
{
  int c = a->prefix_hash - b->prefix_hash;
  if(!c) {
    c = str_diff(a->prefix.s, b->prefix.s);
    if(!c) {
      c = a->type - b->type;
      if(!c) {
	c = dns_random(2);
	if(!c)
	  c = -1;
      }
    }
  }
  return c;
}

void sql_record_sort(void)
{
  unsigned i;
  sql_record* rec;
  sql_record* prev;
  
  for(i = 0, rec = sql_records; i < sql_record_count; ++i, ++rec)
    rec->prefix_hash = cdb_hash(rec->prefix.s, rec->prefix.len);

  qsort(sql_records, sql_record_count, sizeof(sql_record), cmp_records);
  
  for(i = 0, rec = sql_records + sql_record_count-1, prev = 0;
      i < sql_record_count; ++i, --rec) {
    if(!prev || prev->prefix_hash != rec->prefix_hash ||
       str_diff(prev->prefix.s, rec->prefix.s))
      rec->prefix_count = 1;
    else
      rec->prefix_count = prev->prefix_count + 1;
    prev = rec;
  }
}

sql_record* sql_record_select(char* prefix)
{
  unsigned length = dns_domain_length(prefix);
  uint32 hash = cdb_hash(prefix, length);
  sql_record* rec;
  unsigned i;
  
  for(rec = sql_records, i = 0; i < sql_record_count;
      i += rec->prefix_count, rec += rec->prefix_count) {
    if(hash == rec->prefix_hash &&
       !str_diff(prefix, rec->prefix.s))
      return rec;
  }
  return 0;
}
