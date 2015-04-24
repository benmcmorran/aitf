#include "AITF_packet.h"

AITF_packet::AITF_packet(uint8_t ptype, uint64_t nonce1, uint64_t nonce2, uint32_t pointer, vector<RRFilter> rfilters, IP::address_type dest_addr):
	_packet_type(ptype), _nonce1(nonce1), _nonce2(nonce2), aitf_info(rfilters, dest_addr, pointer){}

AITF_packet::AITF_packet(uint8_t ptype, uint64_t nonce1, uint64_t nonce2, AITF_identity info): 
	_packet_type(ptype), _nonce1(nonce1), _nonce2(nonce2), aitf_info(info.filters(), info.victim(), info.pointer()){}

AITF_packet::AITF_packet(const uint8_t *data, uint32_t size){
	_packet_type = ntohll(*((uint8_t*)data));
	data += 1;

	_nonce1 = ntohll(*((uint64_t*)data));
	data += 8;

	_nonce2 = ntohll(*((uint64_t*)data));
	data += 8;

	_size = ntohll(*((uint32_t*)data));
	data += 4;

	//TODO:: IMPLEMENT
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

vector<RRFilter> AITF_packet::filter_table(){
	return fitlers;
}