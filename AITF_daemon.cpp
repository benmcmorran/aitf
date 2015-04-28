#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/resource.h>
#include <asm/errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <malloc.h>
#include <string.h>
#include <utility>
#include <map>
#include <sys/types.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <linux/netfilter.h>  

#include <tins/tins.h>
#include "HostMapping.h"
#include "AITF_packet.h"
#include "AITF_connect_state.h"
//#include "AITF_identity_hash.h"

#define TLONG 30

using namespace Tins;
using namespace std;

extern HostMapping hosts;

map<AITF_identity, AITF_connect_state> ostate_table;
map<AITF_identity, AITF_connect_state> istate_table;

vector<RRFilter> block_rules;

typedef enum{
	ENFORCE, REQUEST, VERIFY, CORRECT, BLOCK, CEASE
} AITF_type;

typedef struct thread_data{
	IP::address_type addr;
	char buff[1500];
	ssize_t size;
} thread_data;


uint64_t generateNonce(){
	return 1232;
}

int block_verdict(RREntry r, IP::address_type addr){
	struct timeval start_time;
    gettimeofday(&start_time, NULL);
	int verdict;
	int bypass = start_time.tv_sec;

	for (int i = 0; i < block_rules.size(); i++){
		if (bypass > block_rules.at(i).ttl()){
			continue;
		}
		verdict = block_rules.at(i).match(r, addr);
		if (verdict == 1){
			return NF_ACCEPT;
		}
		if (verdict == 0){
			return NF_DROP;
		}
	}
	return NF_ACCEPT;
}

void send_AITF_message(AITF_packet pack, IP::address_type addr){

	cout << "SENDING PACKET: DEST: " << addr.to_string();
	cout << pack.to_string();

	uint8_t* data = (uint8_t*)malloc(pack.packet_size());
	pack.serialize(data, pack.packet_size());


	int status, sd, len, s, r;
	struct addrinfo hints;
	struct addrinfo *servinfo, *p; // will point to the results

	const char *url, *port;

	port = "11467";
	url = addr.to_string().c_str();

	memset(&hints, 0 , sizeof(hints)); // make sure the stuct is empty
	hints.ai_family = AF_INET; // only IPv4
	hints.ai_socktype = SOCK_DGRAM; // Use a UDP connection
	// getaddrinfo() - fills out an address structure for us with the destination server's info
	if((status = getaddrinfo(url, port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
		return;
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
		return;
	}
	freeaddrinfo(servinfo);

	s = send(sd, data, pack.packet_size(), 0);

	close(sd);

	return;
}

uint64_t generateRandomValue(IP::address_type addr, int x){
	return 42;
}


void AITF_escalation(AITF_packet pack){
	cout << endl << pack.to_string() << endl;

	uint64_t nonce1 = generateNonce();
	ostate_table[pack.identity()].set_nonce1(nonce1);

	AITF_packet request = AITF_packet((uint8_t)REQUEST, nonce1, (uint64_t)0, ostate_table[pack.identity()].currentRoute()+1, pack.identity());

	ostate_table[pack.identity()].set_currentRoute(request.pointer());

	cout << endl << request.to_string() << endl;


	if (request.identity().filters().size() > request.pointer()){
		send_AITF_message(request, request.identity().filters()[request.pointer()].address());
	}else{
		ostate_table.erase(request.identity());
	}
	return;
}

void AITF_enforce(AITF_packet pack, IP::address_type addr){
	cout << "Host enabled " << hosts.isEnabledHost(addr) << " " << addr << endl;
	if (hosts.isEnabledHost(addr)){
		struct timeval start_time;
    	gettimeofday(&start_time, NULL);
		int bypass = start_time.tv_sec;

		if (ostate_table.count(pack.identity()) && ostate_table[pack.identity()].ttl() <= bypass){

			ostate_table[pack.identity()].set_ttl(bypass+TLONG-TLONG/6);

			AITF_escalation(pack);
		}else{
			AITF_connect_state cstate(0,0,0);
			ostate_table.insert(std::make_pair(pack.identity(), cstate));
			
			uint64_t nonce1 = generateNonce();
			ostate_table[pack.identity()].set_nonce1(nonce1);
			ostate_table[pack.identity()].set_ttl(bypass+TLONG-TLONG/6);
			ostate_table[pack.identity()].set_currentRoute(1);

			AITF_packet request = AITF_packet((uint8_t)REQUEST, nonce1, (uint64_t)0, (uint32_t)1, pack.identity().filters(), pack.identity().victim(), pack.identity().size());

			if (request.identity().filters().size() >= 2){
				send_AITF_message(request, request.identity().filters()[1].address());
			}else{
				ostate_table.erase(request.identity());
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
		if (ip_addrs[x].addresses().ip_addr == pack.identity().filters()[pack.pointer()].address()){
			addr = ip_addrs[x].addresses().ip_addr;
			break;
		}
	}

	RRFilter rent = pack.identity().filters()[pack.pointer()];

	//Check the random numbers
	if (generateRandomValue(pack.identity().victim(),1) == rent.random_number_1() || generateRandomValue(pack.identity().victim(),1) == rent.random_number_2()){
		// SEND VERIFY
		AITF_connect_state cstate(0,0,0);
		istate_table[pack.identity()] = cstate;

		// SET NONCE2
		uint64_t nonce2 = generateNonce();
		istate_table[pack.identity()].set_nonce2(nonce2);

		AITF_packet verify((uint8_t)VERIFY, pack.nonce1(), nonce2, pack.pointer(), pack.identity());

		send_AITF_message(verify, verify.identity().victim());
	}else{
		vector<RRFilter> nfilter = pack.identity().filters();
		// SEND CORRECT
		uint64_t r1 = generateRandomValue(pack.identity().victim(), 1);
		uint64_t r2 = generateRandomValue(pack.identity().victim(), 2);
		AITF_packet correct = AITF_packet((uint8_t)CORRECT, pack.nonce1(), (uint64_t)0, pack.pointer(), r1, r2, pack.identity());

		send_AITF_message(correct, correct.identity().victim());
	}


	return;
}

void AITF_verify(AITF_packet pack){
	struct timeval start_time;
    gettimeofday(&start_time, NULL);
	int bypass = start_time.tv_sec;
	
	if (ostate_table.count(pack.identity()) && ostate_table[pack.identity()].ttl() <= bypass){
		
		ostate_table[pack.identity()].set_ttl(bypass+TLONG-TLONG/6);

		AITF_connect_state cstate = ostate_table.at(pack.identity());
		if (cstate.nonce1() == pack.nonce1()){
			AITF_packet block((uint8_t)BLOCK, (uint64_t)0, pack.nonce2(), pack.pointer(), pack.identity());

			send_AITF_message(block, pack.identity().filters()[pack.pointer()].address());
		}
	}
	return;
}

void AITF_correct(AITF_packet pack){
	struct timeval start_time;
    gettimeofday(&start_time, NULL);
	int bypass = start_time.tv_sec;

	if (ostate_table.count(pack.identity())){

		ostate_table[pack.identity()].set_ttl(bypass+TLONG-TLONG/6);

		AITF_connect_state cstate = ostate_table.at(pack.identity());
		if (cstate.nonce1() == pack.nonce1()){
			vector<RRFilter> rent = pack.identity().filters();
			rent[pack.pointer()].set_random_number_1(pack.crn1());
			rent[pack.pointer()].set_random_number_2(pack.crn2());
			rent[pack.pointer()].set_match_type(2);
			AITF_packet enforce = AITF_packet((uint8_t)ENFORCE, (uint64_t)0, (uint64_t)0, (uint32_t)0, rent, pack.identity().victim(), rent.size());

			ostate_table.erase(pack.identity());
			ostate_table[enforce.identity()] = cstate;

			AITF_enforce(enforce, pack.identity().victim());
		}
	}
	return;
}

void AITF_block(AITF_packet pack){
	if (istate_table.count(pack.identity())){
		AITF_connect_state cstate = istate_table.at(pack.identity());
		if (cstate.nonce2() == pack.nonce2()){
			vector<RRFilter> rent = pack.identity().filters();

			RRFilter block = rent.at(pack.pointer()-1);

			cout << endl << "INSTALLING BLOCK: " << block.to_string() << endl;

			struct timeval start_time;
    		gettimeofday(&start_time, NULL);

			block.set_ttl(start_time.tv_sec + TLONG);
			block_rules.push_back(block);

			istate_table.erase(pack.identity());
		}
	}

	return;
}

void AITF_cease(AITF_packet pack){
	// NEVER CEASE! MARCH FORWARDS!
	return;
}

void AITF_action(thread_data* data){

	AITF_packet apacket = AITF_packet((uint8_t*)data->buff, data->size);

	cout << apacket.to_string();

	switch(apacket.packet_type())
	{
		case 0:
			AITF_enforce(apacket, data->addr);
			break;
		case 1:
			AITF_request(apacket);
			break;
		case 2:
			AITF_verify(apacket);
			break;
		case 3:
			AITF_correct(apacket);
			break;
		case 4:
			AITF_block(apacket);
			break;
		case 5:
		default:
			AITF_cease(apacket);
	}
	free(data);
}

void AITF_daemon(void* data){
	int portNumber = 11467;

	struct sockaddr_in serv_addr, client_addr; 
	int fd = 0;
	int fdlisten = 0;
	int fdconn = 0;
	int out = 0;
	unsigned int client = sizeof(client_addr);
	     
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
	fdlisten = fd; 

	ssize_t tsdata;
	thread_data* buff;
	while(1) 
	{ 
		buff = (thread_data*) malloc(sizeof(thread_data));
		tsdata =  recvfrom(fdlisten, buff->buff, 1500, 0, (struct sockaddr *)&client_addr, &client);

		if (tsdata > 0){
			uint32_t conn_addr = client_addr.sin_addr.s_addr;
			buff->addr = IP::address_type(conn_addr);
			buff->size = tsdata;
			//pthread_t helper;
			//pthread_create(&helper, NULL, (void*(*)(void*))AITF_action, buff);
			AITF_action(buff);
		}else{
			free(buff);
		}
	}
}

int intializeAITF(void* filtertable){
	int aitf_thread = 0;
	pthread_t helper;
	pthread_create(&helper, NULL, (void*(*)(void*))AITF_daemon, filtertable);
 
}