#ifndef SQLDNS_H
#define SQLDNS_H

#define DNS_NUM_A 1
#define DNS_NUM_NS 2
#define DNS_NUM_SOA 6
#define DNS_NUM_PTR 12
#define DNS_NUM_MX 15
#define DNS_NUM_ANY 255

struct sql_record 
{
  int type;
  unsigned long ttl;
  char ip[4];
  unsigned long distance;
  stralloc name;
};
typedef struct sql_record sql_record;

#define SQL_RECORD_MAX 256
sql_record sql_records[SQL_RECORD_MAX];

void sql_connect(void);
int sql_select_domain(char* domain, unsigned long* id, char** name);
unsigned sql_select_entries(unsigned long domain, char* prefix,
			    int lookup_A, int lookup_MX);

int stralloc_cat_dns_to_sql(stralloc* s, char* name);
int stralloc_catb_dns_to_sql(stralloc* s, char* name, int bytes);

void sql_exec(char* q);
unsigned sql_fetch(unsigned row, unsigned col, char** result);
int sql_fetch_ulong(unsigned row, unsigned col, unsigned long* result);
int sql_fetch_ip4(unsigned row, unsigned col, char result[4]);
unsigned sql_ntuples(void);

#endif
