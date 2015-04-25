/*
John Breen
Andrew Botelho
Iveri Prangishvili
*/

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/resource.h>
#include <asm/errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <malloc.h>
#include <string.h>

int main(int argc, char **argv)
{
    int portNumber;
    if(argc <2){
        portNumber = 9191;
    }
    else{
        portNumber = atoi(argv[1]);
    }
    
    struct sockaddr_in serv_addr, client_addr;
    int fd = 0;
    int fdconn = 0;
    int out = 0;
    
    // Establish the socket that will be used for listening
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    printf("Socket: %dn", fd);
    
    // Do a bind of that socket
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(portNumber);
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind( fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    
    // Set up to listen
    listen( fd, 100);    
    
    struct timeval start_time, end_time, last_measurement;
    int goodCount = 0;
    int badCount = 0;
    uint8_t buffer[1500];
    gettimeofday(&start_time, NULL);
    last_measurement = start_time;
    while(1)
    {
        ssize_t size = recv(fd, buffer, 1500, 0);
        if (size > 0) {
            if (buffer[0] == 0) goodCount++;
            else badCount++;
        }

        gettimeofday(&end_time, NULL);
        long long measured = (end_time.tv_sec - last_measurement.tv_sec) * 1000000 + (end_time.tv_usec - last_measurement.tv_usec);
        if (measured >= 0.1 * 1000000) {
            printf("good %.1f\tbad %.1f\n", goodCount * 8.0 * 1000.0 * 0.000001 / (measured / 1000000.0), badCount * 8.0 * 1000.0 * 0.000001 / (measured / 1000000.0));
            goodCount = badCount = 0;
            last_measurement = end_time;
        }
    }
}
