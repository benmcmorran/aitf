#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/resource.h>
#include <asm/errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <malloc.h>
#include <string.h>
#include <map>
#include <tins/tins.h>

using namespace Tins;

extern HostMapping host;

unordered_map<AITF_identity, AITF_connect_state> ostate_table;
unordered_map<AITF_identity, AITF_connect_state> istate_table;

typedef enum{
	enforce, request, verify, correct, block, cease
} AITF_type;

typedef struct thread_data{
	IP::address_type addr;
	char buff[1500];
	ssize_t size;
} thread_data;

void AITF_enforce(AITF_packet pack, IP::address_type addr){
	if (host.isEnabledHost(addr)){
		if (ostate_table.find(pack.identity())){
			AITF_escalation(pack);
		}else{
			AITF_connect_state cstate = AITF_connect_state(pack);
			ostate_table[pack.identity()] = cstate;
			AITF_packet request = AITF_packet(AITF_type.request, generateNonce(), 0, pack.identity());

			if (request.identity().filters().size() >= 2){
				send_AITF_message(request, request.identity().filters()[1].addr);
			}else{
				map.erase(request.identity());
			}
		}
	}
	return;
}

void AITF_request(AITF_packet pack){
	vector<NetworkInterface> ip_addrs = NetworkInterface::all();
	IP::address_type addr;
	int x;
	int y;
	for (x = ip_addrs.size()-1; x >= 0; x--){
		if (ip_addrs[x].addresses().ip_addr == pack.identity().filters()[pack.identity().pointer()].addr){
			addr = ip_addrs[x].addresses().ip_addr;
			break;
		}
	}

	RREntry rent = pack.identity().filters()[pack.identity().pointer()];

	//Check the random numbers
	if (getRandomValue(rent.dest_addr,1) == rent.random_number_1() || getRandomValue(rent.dest_addr,1) == rent.random_number_2()){
		// SEND VERIFY
		AITF_connect_state cstate = AITF_connect_state(pack);
		istate_table[pack.identity()] = cstate;
		AITF_packet verify = AITF_packet(AITF_type.verify, pack.nonce1(), generateNonce(), pack.identity());

		send_AITF_message(verify, verify.identity().dest_addr);
	}else{
		// SEND CORRECT
		rent.set_random_number_1(generateRandomValue(rent.dest_addr, 1));
		rent.set_random_number_2(generateRandomValue(rent.dest_addr, 2));
		AITF_packet correct = AITF_packet(AITF_type.correct, pack.nonce1(), 0, pack.identity());

		send_AITF_message(correct, correct.identity().dest_addr);
	}


	return;
}

void AITF_verify(AITF_packet pack){
	if (ostate_table.find(pack.identity())){
		AITF_connect_state cstate = ostate_table[pack.identity()];
		if (cstate.nonce1() == pack.nonce1()){
			AITF_packet block = AITF_packet(AITF_type.block, 0, pack.nonce2(), pack.identity());

			send_AITF_message(block, pack.identity().filters()[cstate.currentRoute()].addr);
		}
	}
	return;
}

void AITF_correct(AITF_packet pack){
	if (ostate_table.find(pack.identity())){
		AITF_connect_state cstate = ostate_table[pack.identity()];
		if (cstate.nonce1() == pack.nonce1()){
			RREntry rent = pack.identity().filters()[cstate.currentRoute()].set_match_type(2);
			AITF_enforce(pack);
		}
	}
	return;
}

void AITF_block(AITF_packet pack){
	return;
}

void AITF_cease(AITF_packet pack){
	// NEVER CEASE! MARCH FORWARDS!
	return;
}

void AITF_request(thread_data* data){

	AITF_packet apacket = AITF_packet((uint8_t*)data->buff, data->size);

	switch(apacket.packet_type())
	{
		case 1:
			AITF_enforce(apacket, data->addr);
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
	free(data);
}

void AITF_daemon(void* data){
	int portNumber = 11467;

	struct sockaddr_in serv_addr, client_addr; 
	int fd = 0;
	int fdListen = 0;
	int fdconn = 0;
	int out = 0;
	int client = sizeof(client_addr);
	     
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

	ssize_t tsdata;
	thread_data* buff;
	while(1) 
	{ 
		buff = (thread_data*) malloc(sizeof(thread_data));
		tsdata =  recvfrom(fdlisten, buff->buff, 1500, 0, (struct sockaddr *)&client_addr, &client);

		if (tsdata > 0){
			uint32_t conn_addr = client_addr.s_addr;
			buff->addr = IP::address_type(conn_addr);
			buff->size = tsdata;
			out = CreateAThread( (void *)(*AITF_request), buff); 
		}else{
			free(buff);
		}
	}
}

int intializeAITF(void* filtertable){
	int aitf_thread = 0;

	aitf_thread = CreateAThread( (void *)(*AITF_daemon), filtertable); 
}