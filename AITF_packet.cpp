#include "AITF_packet.h"

AITF_packet::AITF_packet(uint8_t ptype, uint64_t nonce1, uint64_t nonce2, uint32_t size, vector<RRFilter> rfilters, uint32_t dest_addr):
	packet_type(ptype), nonce1(nonce1), nonce2(nonce2), size(size), filters(rfilters), dest_addr(dest_addr){}


AITF_packet::AITF_packet(uint8_t ptype, uint64_t nonce1, uint64_t nonce2, uint32_t size, uint32_t dest_addr):
	packet_type(ptype), nonce1(nonce1), nonce2(nonce2), size(size), filters(), dest_addr(dest_addr){}

AITF_packet::AITF_packet(const uint8_t *data, uint32_t size) : filters(){

	packet_type = ntohll(*((uint8_t*)data));
	data += 1;

	nonce1 = ntohll(*((uint64_t*)data));
	data += 8;

	nonce2 = ntohll(*((uint64_t*)data));
	data += 8;

	size = ntohll(*((uint32_t*)data));
	data += 4;

	for (int i = 0; i < size; i++) {
        filters.push_back(RRFilter(data, sizeof(RRFilter));
        position += sizeof(RRFilter);
    }
}

uint8_t AITF_packet::packet_type(){
	return packet_type;
}

uint64_t AITF_packet::nonce1(){
	return nonce1;
}

uint64_t AITF_packet::nonce2(){
	return nonce2;
}

uint32_t AITF_packet::size(){
	return size;
}

vector<RRFilter> AITF_packet::filter_table(){
	return fitlers;
}

uint32_t AITF_packet::dest_addr(){
	return dest_addr;
}