#include "dns.h"
#include "scan.h"

int main(int argc, char* argv[])
{
  unsigned i;
  unsigned j;
  stralloc out = {0,0,0};
  stralloc fqdn = {0,0,0};
  unsigned long loops;
  
  if(argc < 3) return 1;
  if(argv[1][scan_ulong(argv[1], &loops)]) return 1;

  for(i = 0; i < loops; i++) {
    for(j = 2; j < argc; j++) {
      stralloc_copys(&fqdn, argv[j]);
      stralloc_copys(&out, "");
      dns_ip4(&out, &fqdn);
    }
  }
  return 0;
}
