#ifndef SQLDNS_H
#define SQLDNS_H

#define DNS_NUM_A 1
#define DNS_NUM_NS 2
#define DNS_NUM_SOA 6
#define DNS_NUM_PTR 12
#define DNS_NUM_MX 15
#define DNS_NUM_TXT 16
#define DNS_NUM_ANY 255

#include "cdb.h"
#include "stralloc.h"
#include <sys/time.h>

struct sql_record 
{
  stralloc prefix;

  /* Prefix grouping information */
  uint32 prefix_hash;
  unsigned prefix_count;
  
  /* Data for this record */
  unsigned long type;
  time_t ttl;
  char ip[4];
  unsigned long distance;
  stralloc name;
  time_t timestamp;
};
typedef struct sql_record sql_record;

/* Defined by the SQL record module */
extern sql_record* sql_records;
extern unsigned sql_record_size;
extern unsigned sql_record_count;
sql_record* sql_record_alloc(unsigned size);
void sql_record_sort(void);
sql_record* sql_record_select(char* prefix);

#define SQLNULL ((unsigned)-1)

/* Defined by the low-level SQL module */
void sql_connect(void);
void sql_exec(char* q);
unsigned sql_fetch(unsigned row, unsigned col, char** result);
unsigned sql_ntuples(void);

/* Defined by the SQL schema module */
int sql_select_domain(char* domain, stralloc* name);
unsigned sql_select_ip4(char ip[4]);

#endif
