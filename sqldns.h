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
  stralloc prefix;
  int type;
  unsigned long ttl;
  char ip[4];
  unsigned long distance;
  stralloc name;
};
typedef struct sql_record sql_record;

#define SQL_RECORD_MAX 256
extern sql_record sql_records[SQL_RECORD_MAX];

/* Defined by the low-level SQL module */
void sql_connect(void);
void sql_exec(char* q);
unsigned sql_fetch(unsigned row, unsigned col, char** result);
unsigned sql_ntuples(void);

/* Defined by the SQL schema module */
int sql_select_domain(char* domain, unsigned long* id, char** name);
unsigned sql_select_entries(unsigned long domain, stralloc* prefixes);
unsigned sql_select_ip4(char ip[4]);

#endif