#include "buffer.h"
#include "byte.h"
#include "dns.h"
#include "dd.h"
#include "env.h"
#include "ip4.h"
#include "response.h"
#include "scan.h"
#include "str.h"
#include "strerr.h"
#include <time.h>
#include "sql.h"

char *fatal = "pgsqldns: fatal: ";

struct nameserver
{
  char name[256];
  char ip[4];
  unsigned long name_ttl;
  unsigned long ip_ttl;
};

static unsigned nameserver_count;
static struct nameserver nameservers[10];

#define DEFAULT_NS_NAME_TTL 86400
#define DEFAULT_NS_IP_TTL 86400

static stralloc sql_query;

static int sql_fetch_ip(unsigned row, unsigned col, char ip[4])
{
  char* data;
  unsigned length;

  length = sql_fetch(row, col, &data);
  return length > 0 && ip4_scan(data, ip) == length;
}

static int sql_fetch_ulong(unsigned row, unsigned col, unsigned long* result)
{
  char* data;
  unsigned length;

  length = sql_fetch(row, col, &data);
  return length > 0 && scan_ulong(data, result) == length;
}

static unsigned long domain_id;
static stralloc domain_name;
static stralloc domain_prefix;

static stralloc dns_name;

static int name_to_dns(char* name, int add_domain)
     /* Convert the given text domain name into DNS binary format.
      * Set add_domain to:
      * 0: never add the domain
      * 1: add domain_name to unqualified domains
      * 2: always add domain_name */
{
  int is_qualified = 0;
  if(!stralloc_copys(&dns_name, "")) return 0;
  while(*name == '.')
    ++name;
  while(*name) {
    char* start = name;
    unsigned char tmp[1];
    while(*name && *name != '.')
      ++name;
    tmp[0] = name - start;
    if(!stralloc_catb(&dns_name, tmp, 1)) return 0;
    if(!stralloc_catb(&dns_name, start, tmp[0])) return 0;
    if(*name == '.')
      is_qualified = 1;
    while(*name == '.')
      ++name;
  }
  if(add_domain > is_qualified)
    return stralloc_cat(&dns_name, &domain_name);
  else
    return stralloc_0(&dns_name);
}

static int parse_nameserver(unsigned ns, char* env)
{
  unsigned len;
  unsigned long name_ttl = DEFAULT_NS_NAME_TTL;
  unsigned long ip_ttl = DEFAULT_NS_IP_TTL;
  struct nameserver* nsptr = nameservers+ns;
  
  len = str_chr(env, ':');
  if(!len || len > 255) return 0;
  env[len] = 0;
  if(!name_to_dns(env, 0)) return 0;
  env += len+1;
  byte_copy(nsptr->name, dns_name.len, dns_name.s);
  if(!(len = ip4_scan(env, nsptr->ip))) return 0;
  env += len;
  if(*env) return 0;
  nsptr->name_ttl = name_ttl;
  nsptr->ip_ttl = ip_ttl;
  return 1;
}

static void parse_nameservers(void)
{
  unsigned i;
  unsigned j;
  char envname[4] = "NS#";
  for(i = j = 0; i < 10; i++) {
    char* nsline;
    envname[2] = i + '0';
    nsline = env_get(envname);
    if(nsline) {
      if(!parse_nameserver(j, nsline))
	strerr_die3x(111,fatal,"Could not parse nameserver line in ",envname);
      ++j;
    }
  }
  if(j == 0)
    strerr_die2x(111,fatal,"No nameservers were parsed");
  nameserver_count = j;
}
  
void initialize(void)
{
  char* sqlcmd;

  parse_nameservers();

  sql_connect();

  sqlcmd = env_get("SQLSETUP");
  if(sqlcmd)
    sql_exec(sqlcmd);
}

static int stralloc_cat_dns_to_name(stralloc* s, char* name)
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

static int stralloc_catb_dns_to_name(stralloc* s, char* name, int bytes)
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

static void ulong_to_bytes(unsigned long num, unsigned char bytes[4])
{
  bytes[3] = num & 0xff; num >>= 8;
  bytes[2] = num & 0xff; num >>= 8;
  bytes[1] = num & 0xff; num >>= 8;
  bytes[0] = num & 0xff;
}

static void ushort_to_bytes(unsigned short num, unsigned char bytes[2])
{
  bytes[1] = num & 0xff; num >>= 8;
  bytes[0] = num & 0xff;
}

static int response_addulong(unsigned long num)
{
  char bytes[4];
  ulong_to_bytes(num, bytes);
  return response_addbytes(bytes, 4);
}

static int response_addushort(unsigned short num)
{
  char bytes[2];
  ushort_to_bytes(num, bytes);
  return response_addbytes(bytes, 2);
}

/* Convert ttl to bytes and call response_rstart */
static int response_rstartn(char* q, char type[2], unsigned long ttl)
{
  char ttl_bytes[4];
  ulong_to_bytes(ttl, ttl_bytes);
  return response_rstart(q,type,ttl_bytes);
}

static unsigned records;
static unsigned additional;

/* Build a complete A response */
static int response_A(char* q, unsigned long ttl, char ip[4], int additional)
{
  if(!response_rstartn(q,DNS_T_A,ttl)) return 0;
  if(!response_addbytes(ip, 4)) return 0;
  response_rfinish(additional ? RESPONSE_ADDITIONAL : RESPONSE_ANSWER);
  ++records;
  return 1;
}

/* Build a complete MX response */
static int response_MX(char* q, unsigned long ttl, unsigned dist, char* name)
{
  if(!response_rstartn(q,DNS_T_MX,ttl)) return 0;
  if(!response_addushort(dist)) return 0;
  if(!response_addname(name)) return 0;
  response_rfinish(RESPONSE_ANSWER);
  ++records;
  return 1;
}

static int response_NS(char* q, unsigned long ttl, char* ns, int authority)
{
  if(!response_rstartn(q,DNS_T_NS,ttl)) return 0;
  if(!response_addname(ns)) return 0;
  response_rfinish(authority ? RESPONSE_AUTHORITY : RESPONSE_ANSWER);
  ++records;
  return 1;
}

static int response_SOA(unsigned long ttl, int authority)
{
  unsigned long serial = time(0);
  unsigned long refresh = 4096;
  unsigned long retry = 256;
  unsigned long expire = 65536;
  unsigned long minimum = ttl;

  if(!stralloc_copyb(&dns_name, "\12hostmaster", 11)) return 0;
  if(!stralloc_cat(&dns_name, &domain_name)) return 0;
  if(!stralloc_0(&dns_name)) return 0;

  if(!response_rstartn(domain_name.s,DNS_T_SOA,ttl)) return 0;
  if(!response_addname(nameservers[0].name)) return 0;
  if(!response_addname(dns_name.s)) return 0;
  if(!response_addulong(serial)) return 0;
  if(!response_addulong(refresh)) return 0;
  if(!response_addulong(retry)) return 0;
  if(!response_addulong(expire)) return 0;
  if(!response_addulong(minimum)) return 0;
  response_rfinish(authority ? RESPONSE_AUTHORITY : RESPONSE_ANSWER);
  ++records;
  return 1;
}

#define LOG(MSG) buffer_putsflush(buffer_1, MSG "\n")

static int query_database(char* q)
{
  char* domain;
  unsigned i;
  
  if(!stralloc_copys(&sql_query,
		     "SELECT id,name "
		     "FROM domain "
		     "WHERE name='"))
    return 0;
  domain = q;
  for(i = 0; *domain; ++i, domain += *domain+1) {
    if(i)
      if(!stralloc_cats(&sql_query, " OR name='")) return 0;
    if(!stralloc_cat_dns_to_name(&sql_query, domain)) return 0;
    if(!stralloc_append(&sql_query, "'")) return 0;
  }
  if(!stralloc_cats(&sql_query,
		    " ORDER BY length(name) DESC LIMIT 1"))
    return 0;
  if(!stralloc_0(&sql_query)) return 0;
  sql_exec(sql_query.s);
  if(sql_ntuples() != 1) return 0;
  if(!sql_fetch_ulong(0, 0, &domain_id)) return 0;
  
  sql_fetch(0, 1, &domain);
  if(!name_to_dns(domain, 0)) return 0;
  domain = dns_domain_suffix(q, dns_name.s);
  
  /* domain now points to the suffix part of the input query */
  /* Copy the first part of the query into domain_prefix... */
  if(!stralloc_copyb(&domain_prefix, q, domain-q)) return 0;
  if(!stralloc_0(&domain_prefix)) return 0;
  /* ...and the rest into domain_name */
  if(!stralloc_copyb(&domain_name,domain,dns_domain_length(domain))) return 0;
  
  if(!stralloc_copys(&sql_query,
		     "SELECT ttl,ip,mx_name1,mx_name2 "
		     "FROM entry "
		     "WHERE domain=")) return 0;
  if(!stralloc_catulong0(&sql_query, domain_id, 0)) return 0;
  if(!stralloc_cats(&sql_query, " AND prefix='")) return 0;
  if(!stralloc_cat_dns_to_name(&sql_query, domain_prefix.s)) return 0;
  if(!stralloc_append(&sql_query, "'")) return 0;
  if(!stralloc_0(&sql_query)) return 0;
  sql_exec(sql_query.s);
  return 1;
}

static int query_add_MX(char* q, unsigned row, unsigned field, unsigned dist)
{
  char* name;
  unsigned long ttl;
  char* domain;
  
  if(!sql_fetch(row, field, &name)) return 1;
  if(!sql_fetch_ulong(row, 0, &ttl)) return 0;
  if(!name_to_dns(name, 1)) return 0;
  if(!response_MX(q,ttl,dist,dns_name.s)) return 0;

  /* If the domain of the added name matches the current domain,
   * add an additional A record */
  domain = dns_domain_suffix(dns_name.s, domain_name.s);
  if(domain) {
    if(additional)
      if(!stralloc_cats(&sql_query, " OR prefix='")) return 0;
    ++additional;
    if(!stralloc_catb_dns_to_name(&sql_query, dns_name.s,
				  domain-dns_name.s)) return 0;
    if(!stralloc_append(&sql_query, "'")) return 0;
  }
  return 1;
}

static int query_add_A(char* q, unsigned row, unsigned field)
{
  char ip[4];
  if(sql_fetch_ip(row, field, ip)) {
    unsigned long ttl;

    sql_fetch_ulong(row, 0, &ttl);
    if(!response_A(q, ttl, ip, 0)) return 0;
  }
  return 1;
}

static int respond_nameservers(int authority)
{
  unsigned i;
  for(i = 0; i < nameserver_count; i++)
    if(!response_NS(domain_name.s,
		    nameservers[i].name_ttl,
		    nameservers[i].name, authority))
      return 0;
  return 1;
}

static int lookup_A;
static int lookup_MX;
static int lookup_NS;
static int lookup_SOA;
static int sent_ns;

static int make_response(char* q)
{
  unsigned row;
  unsigned tuples;

  records = 0;
  additional = 0;

  tuples = sql_ntuples();
  if(tuples == 0) {
    response_nxdomain();
    return 1;
  }

  /* Start up secondary query for additional A records */
  if(lookup_MX) {
    if(!stralloc_copys(&sql_query,
		       "SELECT ttl,ip,prefix "
		       "FROM entry "
		       "WHERE domain=")) return 0;
    if(!stralloc_catulong0(&sql_query, domain_id, 0)) return 0;
    if(!stralloc_cats(&sql_query, " AND (prefix='")) return 0;
  }

  if(domain_prefix.len == 1) {
    if(lookup_SOA && !response_SOA(2560, 0)) return 0;
    if(lookup_NS) {
      if(!respond_nameservers(0)) return 0;
      sent_ns = 1;
    }
  }

  for(row = 0; row < tuples; row++) {
    if(lookup_A)
      if(!query_add_A(q, row, 1)) return 0;
  
    if(lookup_MX) {
      if(!query_add_MX(q, row, 2, 1)) return 0;
      if(!query_add_MX(q, row, 3, 2)) return 0;
    }
  }
  if(lookup_MX)
    if(!stralloc_catb(&sql_query, ")", 2)) return 0;
  return 1;
}

static int respond_authorities(void)
{
  if(!sent_ns &&
     !respond_nameservers(1))
    return 0;
  return 1;
}

int respond_additional(void)
{
  unsigned i;
  if(additional) {
    unsigned row;
    unsigned tuples;
    sql_exec(sql_query.s);
    tuples = sql_ntuples();
    for(row = 0; row < tuples; row++) {
      char ip[4];
      if(sql_fetch_ip(row, 1, ip)) {
	unsigned long ttl;
	char* prefix;
	if(!sql_fetch_ulong(row, 0, &ttl) ||
	   !sql_fetch(row, 2, &prefix)) return 0;
	if(!name_to_dns(prefix, 2)) return 0;
	if(!response_A(dns_name.s,ttl,ip,1)) return 0;
      }
    }
  }
  for(i = 0; i < nameserver_count; i++)
    if(!response_A(nameservers[i].name,
		   nameservers[i].ip_ttl,
		   nameservers[i].ip, 1))
      return 0;
  return 1;
}

#define type_equal(A,B) (((A)[0] == (B)[0]) && ((A)[1] == (B)[1]))

int respond(char *q, char qtype[2] /*, char srcip[4] */)
{
  lookup_A = 0;
  lookup_MX = 0;
  lookup_NS = 0;
  lookup_SOA = 0;
  sent_ns = 0;
  
  if(type_equal(qtype, DNS_T_ANY))
    lookup_A = lookup_MX = lookup_NS = lookup_SOA = 1;
  else if(type_equal(qtype, DNS_T_A))
    lookup_A = 1;
  else if(type_equal(qtype, DNS_T_MX))
    lookup_MX = 1;
  else if(type_equal(qtype, DNS_T_NS))
    lookup_NS = 1;
  else if(type_equal(qtype, DNS_T_SOA))
    lookup_SOA = 1;
  else {
    response[2] &= ~4;
    response[3] &= ~15;
    response[3] |= 5;
    return 1;
  }
  
  if(!query_database(q)) return 0;
  if(!make_response(q)) return 0;
  
  if(!records)
    return response_SOA(2560, 1);
  else
    return respond_authorities() && respond_additional();
}
