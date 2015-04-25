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


#define MAXBUF 1000
#define TOTAL_RECV 25

// Function prototype for the time difference function
struct timeval* time_difference(struct timeval *start, struct timeval *end);

typedef enum {
  GOOD,
  BAD
} TrafficType;

TrafficType uint8_to_traffic_type(uint8_t byte) {
  return byte == 0 ? GOOD : BAD;
}

uint8_t traffic_type_to_byte(TrafficType type) {
  return type == GOOD ? 0 : 1;
}

char* traffic_type_to_string(TrafficType type) {
  return type == GOOD ? "good" : "bad";
}

void generate_payload(uint8_t *buffer, size_t size, TrafficType type) {
  *buffer = traffic_type_to_byte(type);

  size_t i;
  for (i = 1; i < size; i++) {
    buffer[i] = rand();
  }
}

void usage() {
  puts("Usage: ./flow <ip address> [<port>] [--rate <rate>] [--type (good | bad)]");
  exit(1);
}

void parse_args(int argc, char *argv[], char **url, char **port, int *rate, TrafficType *type) {
  if (argc < 2) usage();

  int ip_set = 0;
  *port = "9191";
  *rate = 20;
  *type = GOOD;

  int i;
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--rate") == 0) {
      if (i + 1 < argc) {
        i++;
        *rate = atoi(argv[i]);
      } else usage();
    } else if (strcmp(argv[i], "--type") == 0) {
      if (i + 1 < argc) {
        i++;
        if (strcmp(argv[i], "good") == 0)
          *type = GOOD;
        else if (strcmp(argv[i], "bad") == 0)
          *type = BAD;
        else usage();
      }
    } else if (!ip_set) {
      *url = argv[i];
      ip_set = 1;
    } else {
      *port = argv[i];
    }
  }
}

int main(int argc, char *argv[])
{
  int status, sd, len, s, r;
  uint8_t msg[MAXBUF];
  struct addrinfo hints;
  struct addrinfo *servinfo, *p; // will point to the results

  char *url, *port;
  unsigned int rate; // Mbps
  TrafficType type;
  
  parse_args(argc, argv, &url, &port, &rate, &type);

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

  printf("Sending %s traffic to %s:%s at %d Mbps\n", traffic_type_to_string(type), url, port, rate);

  struct timeval start_time, end_time;
  gettimeofday(&start_time, NULL);
  unsigned int delay = 1000000.0 * (MAXBUF * 8) / (rate * (1 << 20)); // Delay between packets in us
  unsigned int expected = delay * 1000;  // Expected time to send 1000 packets in us

  while (1) {
    int i;
    for (i = 0; i < 1000; i++) {
      generate_payload(msg, MAXBUF, type);
      s = send(sd, msg, MAXBUF, 0);
      usleep(delay);
    }
    
    gettimeofday(&end_time, NULL);

    long long measured = (end_time.tv_sec - start_time.tv_sec) * 1000000 + (end_time.tv_usec - start_time.tv_usec);
    delay *= (double)expected / measured;  // Proportional control with Kp = 1
    start_time = end_time;
  }
  
  close(sd);

  return 0;
}
