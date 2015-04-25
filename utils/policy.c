/* 
John Breen
Andrew Botelho
Iveri Prangishvili
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <assert.h>

#include <tins/tins.h>
#include "../AITF_packet.h"

using namespace Tins;

typedef enum{
  ENFORCE, REQUEST, VERIFY, CORRECT, BLOCK, CEASE
} AITF_type;

#define MAXBUF 1000
#define TOTAL_RECV 25

int main(int argc, char *argv[])
{  
  RRFilter filter1(0, IP::address_type("192.168.10.10"), 42, 42);
  RRFilter filter2(0, IP::address_type("192.168.100.10"), 42, 42);
  RRFilter filter3(0, IP::address_type("192.168.200.10"), 42, 42);

  std::vector<RRFilter> filters;
  filters.push_back(filter1);
  filters.push_back(filter2);
  filters.push_back(filter3);

  AITF_packet packet(ENFORCE, 0, 0, 2, filters, IP::address_type("192.168.200.20"), 3);

  int status, sd, len, s, r;
  uint8_t msg[MAXBUF];
  struct addrinfo hints;
  struct addrinfo *servinfo, *p; // will point to the results

  const char url[] = "192.168.200.10", port[] = "11467";

  memset(&hints, 0 , sizeof(hints)); // make sure the stuct is empty
  hints.ai_family = AF_INET; // only IPv4
  hints.ai_socktype = SOCK_DGRAM; // Use a UDP connection
  // getaddrinfo() - fills out an address structure for us with the destination server's info
  if((status = getaddrinfo(url, port, &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
    exit(1);
  }

  // loop through all results and connect to the first one we can
  for(p = servinfo; p != NULL; p = p->ai_next) 
  {
    if ((sd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      perror("client: socket");
      continue;
    }
    if((connect(sd, servinfo->ai_addr, servinfo->ai_addrlen)) < 0) {
      close(sd);
      perror("client: connect");
      continue;
    }
    break;
  }
  if (p == NULL) {
    fprintf(stderr, "client: failed to connect\n");
    return 2;
  }
  freeaddrinfo(servinfo);

  while (1) {
    printf("sending packet\n");
    packet.serialize(msg, MAXBUF);
    s = send(sd, msg, packet.packet_size(), 0);
    usleep(1000000);
  }
  
  close(sd);

  return 0;
}
