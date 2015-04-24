#include "AITF_packet.h"

AITF_packet::AITF_packet(uint8_t ptype, uint64_t nonce1, uint64_t nonce2, uint32_t size, vector<RRFilter> rfilters, IP::address_type dest_addr):
	_packet_type(ptype), _nonce1(nonce1), _nonce2(nonce2), _size(size), aitf_info(rfilters, dest_addr){}


AITF_packet::AITF_packet(uint8_t ptype, uint64_t nonce1, uint64_t nonce2, uint32_t size, IP::address_type dest_addr):
	_packet_type(ptype), nonce1(nonce1), nonce2(nonce2), size(size){}

AITF_packet::AITF_packet(uint8_t ptype, uint64_t nonce1, uint64_t nonce2, AITF_identity info): _packet_type(ptype), nonce1(nonce1), nonce2(nonce2){
	aitf_info(info.filters(), info.victim(), info.pointer());
}

AITF_packet::AITF_packet(const uint8_t *data, uint32_t size) : filters(){

	_packet_type = ntohll(*((uint8_t*)data));
	data += 1;

	_nonce1 = ntohll(*((uint64_t*)data));
	data += 8;

	_nonce2 = ntohll(*((uint64_t*)data));
	data += 8;

	_size = ntohll(*((uint32_t*)data));
	data += 4;

	for (int i = 0; i < size; i++) {
        filters.push_back(RRFilter(data, sizeof(RRFilter));
        position += sizeof(RRFilter);
    }
}

uint8_t AITF_packet::packet_type(){
	return _packet_type;
}

uint64_t AITF_packet::nonce1(){
	return _nonce1;
}

uint64_t AITF_packet::nonce2(){
	return _nonce2;
}

uint32_t AITF_packet::size(){
	return _size;
}

vector<RRFilter> AITF_packet::filter_table(){
	return fitlers;
}