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
#include <sys/time.h>
#include <unistd.h>
#include "sqldns.h"

sql_record sql_records[SQL_RECORD_MAX];

char *fatal = "pgsqldns: fatal: ";
char *warning = "pgsqldns: warning: ";

struct nameserver
{
  stralloc name;
  char ip[4];
};

static char in_addr_arpa[] = "\7in-addr\4arpa";

static unsigned random_offset;
static struct timeval now;

static unsigned nameserver_count;
static struct nameserver nameservers[10];

#define DEFAULT_NS_NAME_TTL 65536
#define DEFAULT_NS_IP_TTL 65536

static unsigned long ns_name_ttl;
static unsigned long ns_ip_ttl;

#define DEFAULT_SOA_TTL     2560
#define DEFAULT_SOA_REFRESH 4096
#define DEFAULT_SOA_RETRY   256
#define DEFAULT_SOA_EXPIRE  65536
#define DEFAULT_SOA_MINIMUM 2560
#define DEFAULT_SOA_MAILBOX "hostmaster"

#define MAX_DYNAMIC_TTL 3600
#define MIN_DYNAMIC_TTL 2

static unsigned long soa_ttl;
static unsigned long soa_refresh;
static unsigned long soa_retry;
static unsigned long soa_expire;
static unsigned long soa_minimum;
static stralloc soa_mailbox;

static unsigned long domain_id;
static stralloc domain_name;
static stralloc domain_prefix;

static stralloc dns_name;

int name_to_dns(stralloc* dns, char* name)
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
  return stralloc_0(dns);
}

static int parse_nameserver(unsigned ns, char* env)
{
  unsigned len;
  struct nameserver* nsptr = nameservers+ns;
  
  len = str_chr(env, ':');
  if(!len || len > 255) return 0;
  env[len] = 0;
  if(!name_to_dns(&nsptr->name, env)) return 0;
  env += len+1;
  if(!(len = ip4_scan(env, nsptr->ip))) return 0;
  env += len;
  if(*env) return 0;
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

void env_get_ulong(char* env, unsigned long* out, unsigned long dflt)
{
  char* tmp = env_get(env);
  if(!tmp) return;
  if(!scan_ulong(tmp, out)) {
    strerr_warn4(warning, "Could not parse $", env, ", ignoring.", 0);
    *out = dflt;
  }
}

#define getenvulong(env,var,default)  
void initialize(void)
{
  char* env;
#if 0
  char seed[128];
  dns_random_init(seed);
#endif
  parse_nameservers();
  sql_connect();
  env_get_ulong("NS_IP_TTL",   &ns_ip_ttl,   DEFAULT_NS_IP_TTL);
  env_get_ulong("NS_NAME_TTL", &ns_name_ttl, DEFAULT_NS_NAME_TTL);
  env_get_ulong("SOA_TTL",     &soa_ttl,     DEFAULT_SOA_TTL);
  env_get_ulong("SOA_REFRESH", &soa_refresh, DEFAULT_SOA_REFRESH);
  env_get_ulong("SOA_RETRY",   &soa_retry,   DEFAULT_SOA_RETRY);
  env_get_ulong("SOA_EXPIRE",  &soa_expire,  DEFAULT_SOA_EXPIRE);
  env_get_ulong("SOA_MINIMUM", &soa_minimum, DEFAULT_SOA_MINIMUM);
  env = env_get("SOA_MAILBOX");
  if(!env)
    env = DEFAULT_SOA_MAILBOX;
  if(!name_to_dns(&soa_mailbox, env))
    strerr_die2x(111,fatal,"Could not create initial SOA mailbox string");
}

static int qualified(unsigned char* s) { return s[s[0]+1]; }

static int stralloc_cat_domain(stralloc* s, stralloc* domain)
{
  if(!s->len) return 0;
  s->s[s->len-1] = domain->s[0];
  return stralloc_catb(s, domain->s+1, domain->len-1);
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
static stralloc additional;

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

static int response_PTR(char* q, unsigned long ttl, char* name)
{
  if(!response_rstartn(q,DNS_T_PTR,ttl)) return 0;
  if(!response_addname(name)) return 0;
  response_rfinish(RESPONSE_ANSWER);
  ++records;
  return 1;
}

static int response_SOA(int authority)
{
  if(!stralloc_copy(&dns_name, &soa_mailbox)) return 0;
  if(!qualified(dns_name.s))
    if(!stralloc_cat_domain(&dns_name, &domain_name)) return 0;

  if(!response_rstartn(domain_name.s,DNS_T_SOA,soa_ttl)) return 0;
  if(!response_addname(nameservers[0].name.s)) return 0;
  if(!response_addname(dns_name.s)) return 0;
  if(!response_addulong(now.tv_sec)) return 0;
  if(!response_addulong(soa_refresh)) return 0;
  if(!response_addulong(soa_retry)) return 0;
  if(!response_addulong(soa_expire)) return 0;
  if(!response_addulong(soa_minimum)) return 0;
  response_rfinish(authority ? RESPONSE_AUTHORITY : RESPONSE_ANSWER);
  ++records;
  return 1;
}

#define LOG(MSG) buffer_putsflush(buffer_1, MSG "\n")

static int dns_domain_join(stralloc* prefix, stralloc* domain)
{
  prefix->s[prefix->len-1] = domain->s[0];
  return stralloc_catb(prefix, domain->s+1, domain->len-1);
}

static int query_domain(char* q)
{
  char* domain;
  if(!sql_select_domain(q, &domain_id, &domain_name)) return 0;
  
  domain = dns_domain_suffix(q, domain_name.s);
  
  /* domain now points to the suffix part of the input query */
  /* Copy the first part of the query into domain_prefix */
  if(!stralloc_copyb(&domain_prefix, q, domain-q)) return 0;
  if(!stralloc_0(&domain_prefix)) return 0;
  
  return 1;
}

static int sent_NS;

static int respond_nameservers(int authority)
{
  unsigned i;
  if(!sent_NS) {
    for(i = 0; i < nameserver_count; i++) {
      unsigned j = (i + random_offset) % nameserver_count;
      if(!response_NS(domain_name.s, ns_name_ttl,
		      nameservers[j].name.s, authority))
	return 0;
    }
  }
  sent_NS = 1;
  return 1;
}

static int lookup_A;
static int lookup_MX;
static int lookup_NS;
static int lookup_PTR;
static int lookup_SOA;

static int query_forward(char* q)
{
  unsigned row;
  unsigned tuples;
  char* domain;
  sql_record* rec;
  
  tuples = sql_select_entries(domain_id, &domain_prefix);
  if(!tuples) {
    response_nxdomain();
    return 1;
  }

  if(domain_prefix.len == 1) {
    if(lookup_SOA)
      if(!response_SOA(0)) return 0;
    if(lookup_NS)
      if(!respond_nameservers(0)) return 0;
  }

  /* Handle timestamps:
   * if TTL=0, timestamp indicates when the record expires
   * otherwise, timestamp indicates when the record should appear */
  for(row = 0; row < tuples; row++) {
    rec = sql_records + row;
    if(rec->timestamp) {
      if(rec->ttl) {
	if(rec->timestamp > now.tv_sec)
	  rec->type = 0;
      }
      else {
	if(rec->timestamp <= now.tv_sec)
	  rec->type = 0;
	else {
	  rec->ttl = rec->timestamp - now.tv_sec;
	  if(rec->ttl > MAX_DYNAMIC_TTL) rec->ttl = MAX_DYNAMIC_TTL;
	  if(rec->ttl < MIN_DYNAMIC_TTL) rec->ttl = MIN_DYNAMIC_TTL;
	}
      }
    }
  }
  
  if(lookup_A) {
    for(row = 0; row < tuples; row++) {
      rec = sql_records + (row + random_offset) % tuples;
      if(rec->type == DNS_NUM_A)
	if(!response_A(q, rec->ttl, rec->ip, 0)) return 0;
    }
  }
  if(lookup_MX) {
    for(row = 0; row < tuples; row++) {
      rec = sql_records + (row + random_offset) % tuples;
      if(rec->type == DNS_NUM_MX) {
	if(!dns_domain_join(&rec->name, &domain_name)) return 0;
	if(!response_MX(q, rec->ttl, rec->distance, rec->name.s)) return 0;
	/* If the domain of the added name matches the current domain,
	 * add an additional A record */
	domain = dns_domain_suffix(rec->name.s, domain_name.s);
	if(domain) {
	  if(!stralloc_catb(&additional, rec->name.s, domain-rec->name.s))
	    return 0;
	  if(!stralloc_0(&additional)) return 0;
	}
      }
    }
  }
  return 1;
}

static int query_reverse(unsigned char* q)
{
  /* Convert the numerical parts of q to an ip array
   * If one of the 4 parts is bad, give a NXDOMAIN response */
  char ip[4];
  unsigned parts;
  char* ptr;
  sql_record* rec;
  
  if(!lookup_PTR)
    return response_SOA(1);
  
  ptr = q;
  for(parts = 0; parts < 4; parts++) {
    unsigned len = *ptr;
    unsigned long num;
    if(!byte_diff(ptr, sizeof in_addr_arpa, in_addr_arpa)) break;
    if(scan_ulong(ptr+1, &num) != len || num > 255) {
      response_nxdomain();
      return 1;
    }
    ip[3-parts] = num;
    ptr += len + 1;
  }
  /* If less than 4 parts were converted:
   *   if domain_prefix is empty:
   *     produce an SOA response
   *   else:
   *     produce a NXDOMAIN response */
  if(parts < 4 || byte_diff(ptr, sizeof in_addr_arpa, in_addr_arpa)) {
    if(domain_prefix.len == 1) {
      if(!response_SOA(0)) return 0;
      if(!respond_nameservers(0)) return 0;
    }
    else
      response_nxdomain();
    return 1;
  }

  switch(sql_select_ip4(ip)) {
  case 0: return 0;
  case 1:
    response_nxdomain();
    return 1;
  }

  rec = &sql_records[0];
  return response_PTR(q, rec->ttl, rec->name.s);
}

int respond_additional(void)
{
  unsigned i;
  if(additional.len) {
    unsigned tuples = sql_select_entries(domain_id, &additional);
    unsigned row;
    for(row = 0; row < tuples; row++) {
      sql_record* rec = &sql_records[row];
      if(rec->type == DNS_NUM_A) {
	if(!dns_domain_join(&rec->prefix, &domain_name)) return 0;
	if(!response_A(rec->prefix.s,rec->ttl,rec->ip,1)) return 0;
      }
    }
  }
  for(i = 0; i < nameserver_count; i++) {
    unsigned j = (i + random_offset) % nameserver_count;
    if(!response_A(nameservers[j].name.s, ns_ip_ttl,
		   nameservers[j].ip, 1))
      return 0;
  }
  return 1;
}

int respond(char *q, unsigned char qtype[2] /*, char srcip[4] */)
{
  /* random_offset = dns_random(~0U); */
  gettimeofday(&now, 0);
  random_offset = now.tv_usec;
  
  lookup_A = 0;
  lookup_MX = 0;
  lookup_NS = 0;
  lookup_PTR = 0;
  lookup_SOA = 0;
  sent_NS = 0;
  
  switch((qtype[0] << 8) | qtype[1]) {
  case DNS_NUM_ANY:
    lookup_A = lookup_MX = lookup_NS = lookup_SOA = lookup_PTR = 1; break;
  case DNS_NUM_A:   lookup_A = 1; break;
  case DNS_NUM_MX:  lookup_MX = 1; break;
  case DNS_NUM_NS:  lookup_NS = 1; break;
  case DNS_NUM_PTR: lookup_PTR = 1; break;
  case DNS_NUM_SOA: lookup_SOA = 1; break;
  default:
    response[2] &= ~4;
    response[3] &= ~15;
    response[3] |= 5;
    return 1;
  }

  if(!query_domain(q)) return 0;
  
  records = 0;
  if(!stralloc_copys(&additional, "")) return 0;

  if(dns_domain_suffix(q, in_addr_arpa)) {
    if(!query_reverse(q)) return 0;
  }
  else {
    if(!query_forward(q)) return 0;
  }
  
  if(!records) {
    if(!response_SOA(1)) return 0;
  }
  else {
    if(!respond_nameservers(1)) return 0;
    if(!respond_additional()) return 0;
  }
  return 1;
}
