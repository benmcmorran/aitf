#include "AITF_packet.h"

AITF_packet::AITF_packet(uint8_t ptype, uint64_t nonce1, uint64_t nonce2, uint32_t pointer, vector<RRFilter> rfilters, IP::address_type dest_addr, uint32_t size):
	_packet_type(ptype), _nonce1(nonce1), _nonce2(nonce2), aitf_info(rfilters, dest_addr, pointer, size){}

AITF_packet::AITF_packet(uint8_t ptype, uint64_t nonce1, uint64_t nonce2, AITF_identity info): 
	_packet_type(ptype), _nonce1(nonce1), _nonce2(nonce2), aitf_info(info.filters(), info.victim(), info.pointer(), info.size()){}

AITF_packet::AITF_packet(const uint8_t *data, uint32_t size){
	_packet_type = *((uint8_t*)data);
	data += 1;

	_nonce1 = *((uint64_t*)data);
	data += 8;

	_nonce2 = *((uint64_t*)data);
	data += 8;

	aitf_info = AITF_identity(data, size-17);
}

void AITF_packet::serialize(uint8_t *data, uint32_t size) const{
    *data = packet_type();
    data += 1;

    *((uint64_t*)data) = nonce1();
    data += 8;

    *((uint64_t*)data) = nonce2();
    data += 8;

    identity().serialize(data, size - 17);
}

uint8_t AITF_packet::packet_type() const{
	return _packet_type;
}

uint64_t AITF_packet::nonce1() const{
	return _nonce1;
}

uint64_t AITF_packet::nonce2() const{
	return _nonce2;
}

AITF_identity AITF_packet::identity() const{
	return aitf_info;
}

int AITF_packet::packet_size(){
	return sizeof(packet_type()) + sizeof(nonce1()) + sizeof(nonce2()) + identity().packet_size();
}

string AITF_packet::to_string(){
	stringstream data;
	data << "PT: " << packet_type() << " N1: " << nonce1() << " N2: " << nonce2() << " ID: " << identity().to_string();
	return data.str();
}