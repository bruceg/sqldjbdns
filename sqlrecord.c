#include "byte.h"
#include "dns.h"
#include "strerr.h"
#include <stdlib.h>
#include "sqldns.h"

sql_record* sql_records = 0;
unsigned sql_record_size = 0;
unsigned sql_record_count = 0;

extern char *fatal;

void sql_record_alloc(unsigned size)
{
  if(size > sql_record_size) {
    sql_records = realloc(sql_records, size * sizeof(sql_record));
    if(!sql_records)
      strerr_die2x(111, fatal, "Could not allocate memory for record set");
    byte_zero(sql_records + sql_record_size*sizeof(sql_record),
	      (size - sql_record_size) * sizeof(sql_record));
    sql_record_size = size;
  }
}

/* The call to dns_random will cause the sorted data set to have like items
 * put into a randomized order */
static int cmp_records(const sql_record* a, const sql_record* b)
{
  int c = a->type - b->type;
  if(!c)
    c = dns_random(3) - 1;
  return c;
}

/* I used a simple insertion sort here since:
 * 1. the number of records is small
 * 2. qsort has a high overhead time for small counts
 * 3. comparisons are fast
 * 4. swapping elements (due to the record size) is slow */
void sql_record_sort(void)
{
  unsigned i;
  for(i = 0; i < sql_record_count-1; i++) {
    sql_record* jmax = sql_records + i;
    unsigned j;
    for(j = i+1; j < sql_record_count; j++)
      if(cmp_records(sql_records+j, jmax) < 0)
	jmax = sql_records+j;
    if(jmax != sql_records+i) {
      sql_record tmp = sql_records[i];
      sql_records[i] = *jmax;
      *jmax = tmp;
    }
  }
}
