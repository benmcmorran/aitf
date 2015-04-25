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

int             WorkThread( void * );            
unsigned int    CreateAThread( void *, int *);   

#define TOTAL_RECV 25000000
int counter = 0;
main(int argc, char **argv)
{

int portNumber;
	if(argc <2){
	portNumber = 9191;
}
else{
portNumber = atoi(argv[1]);
}

    unsigned int            CurrentPriority, MyPid;
    unsigned int            NewThreadID;

struct sockaddr_in serv_addr, client_addr; 
int fd = 0;
int fdListen = 0;
int fdconn = 0;
int out = 0;
int client;
     
// Establish the socket that will be used for listening 
 fd = socket(AF_INET, SOCK_DGRAM, 0); 
printf("Socket: %d\n", fd); 

 // Do a bind of that socket 
serv_addr.sin_family = AF_INET;
serv_addr.sin_port = htons(portNumber);
serv_addr.sin_addr.s_addr = htonl(INADDR_ANY); 
bind( fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)); 
 
 // Set up to listen 
 listen( fd, 10); 
 
 fdListen = fd; 

 
 while(1) 
 { 
 // Do the accept 
client = sizeof(client_addr);
 fdconn = accept( fdListen, (struct sockaddr*)&client_addr, &client); 
 out = CreateAThread( (void *)(*WorkThread), &fdconn); 
}

}        // End of main

//  ///////////////////////////////////////////////////////////////////////
//  This is the code executed by the new thread 
//  ///////////////////////////////////////////////////////////////////////
int    WorkThread( void *data )
{
counter++;
int total = 0;
int fdconn;
fdconn = (int)data;
char buffer[1024];
char msg[1024];
int r, s;
	while(total != TOTAL_RECV){

	r = recv(fdconn, buffer, sizeof(buffer) -1, 0);
	buffer[r+1] = '\0';
	total = total + r;
	bzero(buffer, 1024);
}
printf("Test %d:\n", counter);
printf("Total bytes received: %d\n",total);

int i;
strcpy(msg, "0123456789");
int len = strlen(msg);
printf("Uploading...0%%");
fflush(stdout);

for(i = 0; i<TOTAL_RECV/10; i++){

	s = send(fdconn, msg, len, 0);
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
}
printf("...100%%...SENT!\n");
printf("Total bytes sent: %d\n\n", TOTAL_RECV);
close(fdconn);

}        // End of WorkThread

// ///////////////////////////////////////////////////////////////////////////////
//           CreateAThread
//    Set up a new thread for the caller.  We need to be passed here:
//    Arg1:  The start address of the new thread
//    Arg2:  The address of an int or structure containing data for the new thread
//
//    We return the Thread Handle to the caller.
//    We print lots of errors if something goes wrong.  But we return anyway
// ///////////////////////////////////////////////////////////////////////////////

unsigned int    CreateAThread( void *ThreadStartAddress, int *data )
{
    int                  ReturnCode;
    pthread_t            Thread;
    pthread_attr_t       Attribute;

    ReturnCode = pthread_attr_init( &Attribute );
    if ( ReturnCode != 0 )
        printf( "Error in pthread_attr_init in CreateAThread\n" );
    ReturnCode = pthread_attr_setdetachstate( &Attribute, PTHREAD_CREATE_JOINABLE );
    if ( ReturnCode != 0 )
        printf( "Error in pthread_attr_setdetachstate in CreateAThread\n" );
    ReturnCode = pthread_create( &Thread, &Attribute, ThreadStartAddress, (void *)*data );
    if ( ReturnCode == EINVAL )                        /* Will return 0 if successful */
        printf( "ERROR doing pthread_create - The Thread, attr or sched param is wrong\n");
    if ( ReturnCode == EAGAIN )                        /* Will return 0 if successful */
        printf( "ERROR doing pthread_create - Resources not available\n");
    if ( ReturnCode == EPERM )                        /* Will return 0 if successful */
        printf( "ERROR doing pthread_create - No privileges to do this sched type & prior.\n");

    ReturnCode = pthread_attr_destroy( &Attribute );
    if ( ReturnCode )                                    /* Will return 0 if successful */
        printf( "Error in pthread_mutexattr_destroy in CreateAThread\n" );
    return( (unsigned int)Thread );
}                            // End of CreateAThread
