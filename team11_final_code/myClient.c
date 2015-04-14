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


#define MAXBUF 256
#define TOTAL_RECV 25

// Function prototype for the time difference function
struct timeval* time_difference(struct timeval *start, struct timeval *end);

int main(int argc, char *argv[])
{
  int status, sd, len, s, r;
  char msg[MAXBUF];
  char buffer[MAXBUF];
  struct addrinfo hints;
  struct addrinfo *servinfo, *p; // will point to the results
  
  // Declare and allocate timeval structs
  struct timeval *start_time= (struct timeval*) malloc(sizeof(struct timeval));
  struct timeval *end_time = (struct timeval*) malloc(sizeof(struct timeval));
  struct timeval *difference = (struct timeval*) malloc(sizeof(struct timeval));
 
  if(argc == 1) {
     printf("You need to enter at least an IP address! (Optionally a port number too)\n");
     return 1;
  }
  char *url = argv[1];
  char *port;
  if(argc == 3) {
    port = argv[2];
  }
  else {
    port = "9191";
  }

  memset(&hints, 0 , sizeof(hints)); // make sure the stuct is empty
  hints.ai_family = AF_UNSPEC; // either IPv4 or IPv6
  hints.ai_socktype = SOCK_DGRAM; // Use a TCP connection
  // getaddrinfo() - fills out an address structure for us with the destination server's info
  if((status = getaddrinfo(url, port, &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
    exit(1);
  }

  // loop through all results and connect to the first one we can
  for(p = servinfo; p != NULL; p = p->ai_next) 
  {
    if ((sd = socket(p->ai_family, p->ai_socktype,
			 p->ai_protocol)) == -1) {
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

  // LOW LATENCY FLAG
  // int flag = 1;
  // int result = setsockopt(sd, IPPROTO_TCP, TCP_NODELAY, (char*) &flag, sizeof(int));

  // Upload
  system("upower -d | grep energy:");
  system("upower -d | grep energy-rate:");
  system("sudo ethtool -S wlan0 | grep tx_retries:");
  system("sudo ethtool -S wlan0 | grep tx_packets:");
  bzero(buffer, MAXBUF); // clear the buffer that will receive data from server
  int i;
  strcpy(msg, "0123456789");
  len = strlen(msg);
  gettimeofday(start_time, NULL);
  printf("Uploading...0%%");
  fflush(stdout);
  for(i=0; i<TOTAL_RECV/10; i++)
  {
    if(i == TOTAL_RECV/40) {
      printf("...25%%");
      fflush(stdout);
    }
    if(i == TOTAL_RECV/20) {
      printf("...50%%");
      fflush(stdout);
    }
    if(i == 3*TOTAL_RECV/40) {
      printf("...75%%");
      fflush(stdout);
    }
    s = send(sd, msg, len, 0); // send the message to the server
  }
  
  gettimeofday(end_time, NULL);
  printf("...100%%...SENT!\n");
 
  difference = time_difference(start_time, end_time);
  double milliseconds;
  double bps;
  if (difference != NULL) {
    printf("Upload time: %ld seconds %lf milliseconds\n", difference->tv_sec, ((double)difference->tv_usec)/1000);

    milliseconds = ((double)(difference->tv_sec * 1000)) + (((double)difference->tv_usec)/1000);
    bps = ((double)TOTAL_RECV * 8)/(milliseconds/1000);
    bps = bps/1000000;
    printf("Upload bitrate: %lf Mbps\n\n", bps);
  }
  
  // Download
  system("upower -d | grep energy:");
  system("upower -d | grep energy-rate:");
  system("sudo ethtool -S wlan0 | grep tx_retries:");
  system("sudo ethtool -S wlan0 | grep tx_packets:");
  gettimeofday(start_time, NULL);
  int total = 0;
  printf("Downloading...0%%");
  fflush(stdout);
  while(total != TOTAL_RECV) { // while recv() still has bytes to read from the server, keep filling the buffer and printing
    r = recv(sd, buffer, sizeof(buffer)-1, 0);
    buffer[r+1] = '\0';
    total += r;
    bzero(buffer, MAXBUF);
  }
  gettimeofday(end_time, NULL);
  printf("...100%%...RECEIVED!\n");

  difference = time_difference(start_time, end_time);
  if (difference != NULL) {
    printf("Download time: %ld seconds %lf milliseconds\n", difference->tv_sec, ((double)difference->tv_usec)/1000);

    milliseconds = ((double)(difference->tv_sec * 1000)) + (((double)difference->tv_usec)/1000);
    bps = ((double)TOTAL_RECV * 8)/(milliseconds/1000);
    bps = bps/1000000;
    printf("Download bitrate: %lf Mbps\n\n", bps);
  }
  system("upower -d | grep energy:");
  system("upower -d | grep energy-rate:");
  system("sudo ethtool -S wlan0 | grep tx_retries:");
  system("sudo ethtool -S wlan0 | grep tx_packets:");
  
  freeaddrinfo(servinfo); // free the server's address info
  close(sd); // close the socket

  // display wireless adaptor information such as bitrate
  // system("iwconfig wlan0"); 
  // system("cat /proc/net/wireless");
  // system("iwspy wlan0");

  // display battery usage information
  // system("acpi -b"); 
  // system("sudo powertop");
  // system("powerstat");
  // system("cat /proc/acpi/battery/BAT0/state");
  // system("cat /sys/class/power_supply/BAT0/power_now");
  return 0;
}




// I wrote this time difference function in a previous class
/** Function time_difference
 * Takes two time stamps and determines the difference between them.
 * @param struct timeval *start_time, struct for the start time
 * @param struct timeval *end_time, struct for the end time
 * @return struct timeval*, struct for the difference between the times
 */
struct timeval* time_difference(struct timeval *start, struct timeval *end) {
  // If any of the start or end time values are negative
  if ((start->tv_sec) < 0 || (start->tv_usec) < 0 || 
      (end->tv_sec) < 0 || (end->tv_usec) < 0 ) {
    printf("Error: A timestamp value is a negative number!\n");
    return NULL;
  }
  struct timeval *difference; // Timeval struct for the difference time
  
  difference = (struct timeval*) malloc(sizeof(struct timeval)); // Allocate
  
  // Set fields of difference struct as the difference between the fields
  // of the end and start times. 
  difference->tv_sec = (end->tv_sec) - (start->tv_sec);
  difference->tv_usec = (end->tv_usec) - (start->tv_usec);

  // If the start milliseconds are bigger than the end milliseconds and
  // the end seconds are larger than the start seconds
  // Example: Start: 4 620    End: 5 120
  if ((start->tv_usec) > (end->tv_usec) && (start->tv_sec) < (end->tv_sec)) {
    (difference->tv_sec)--;
    (difference->tv_usec) = (difference->tv_usec) + 1000000;
  }
  // If either difference time value is negative
  if ((difference->tv_sec) < 0 || (difference->tv_usec) < 0 ) {
    printf("Error: A timestamp value of the difference timeval is a negative number!\n");
    return NULL; // End function
  }
  return difference; // Return the difference timeval struct
}
