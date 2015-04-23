#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/resource.h>
#include <asm/errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <malloc.h>
#include <string.h>


void AITF_enforce(AITF_packet pack){
	return;
}

void AITF_request(AITF_packet pack){
	return;
}

void AITF_verify(AITF_packet pack){
	return;
}

void AITF_correct(AITF_packet pack){
	return;
}

void AITF_block(AITF_packet pack){
	return;
}

void AITF_cease(AITF_packet pack){
	return;
}

void AITF_request(int* socketaddr){
	char* data = new char[RECIEVESIZE]();
	string hold;
	int datamt;
	
	while (1)
	{
		if ((datamt = recv(*socketaddr, data, RECIEVESIZE, 0)) <= 0){
			cout << "break: " << datamt << endl;
			break;
		}
		cout << datamt << endl;
		string temp(data, datamt);
		hold += temp;
	}

	AITF_packet apacket = AITF_packet((uint8_t*)hold.c_str(), hold.length());

	switch(apacket.packet_type())
	{
		case 1:
			AITF_enforce(apacket);
			break;
		case 2:
			AITF_request(apacket);
			break;
		case 3:
			AITF_verify(apacket);
			break;
		case 4:
			AITF_correct(apacket);
			break;
		case 5:
			AITF_block(apacket);
			break;
		case 6:
		default:
			AITF_cease(apacket);
	}
}

void AITF_daemon(void* data){
	int portNumber = 11467;

	struct sockaddr_in serv_addr, client_addr; 
	int fd = 0;
	int fdListen = 0;
	int fdconn = 0;
	int out = 0;
	int client;
	     
	// Establish the socket that will be used for listening 
	fd = socket(AF_INET, SOCK_STREAM, 0); 
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
		out = CreateAThread( (void *)(*AITF_request), &fdconn); 
	}
}

int intializeAITF(void* filtertable){
	int aitf_thread = 0;

	aitf_thread = CreateAThread( (void *)(*AITF_daemon), filtertable); 
}