#include "AITF_packet.h"

AITF_packet::AITF_packet(uint8_t ptype, uint64_t nonce1, uint64_t nonce2, uint32_t pointer, vector<RRFilter> rfilters, IP::address_type dest_addr, uint32_t size):
	_packet_type(ptype), _nonce1(nonce1), _nonce2(nonce2), _pointer(pointer), _crn1(0), _crn2(0), aitf_info(rfilters, dest_addr, size){}

AITF_packet::AITF_packet(uint8_t ptype, uint64_t nonce1, uint64_t nonce2, uint32_t pointer, AITF_identity info): 
	_packet_type(ptype), _nonce1(nonce1), _nonce2(nonce2), _pointer(pointer), _crn1(0), _crn2(0), aitf_info(info.filters(), info.victim(), info.size()){}

AITF_packet::AITF_packet(uint8_t ptype, uint64_t nonce1, uint64_t nonce2, uint32_t pointer, uint64_t c1, uint64_t c2, AITF_identity info):
	_packet_type(ptype), _nonce1(nonce1), _nonce2(nonce2), _pointer(pointer), _crn1(c1), _crn2(c2), aitf_info(info.filters(), info.victim(), info.size()){}

AITF_packet::AITF_packet(const uint8_t *data, uint32_t size){
	_packet_type = *((uint8_t*)data);
	data += 1;

	_nonce1 = *((uint64_t*)data);
	data += 8;

	_nonce2 = *((uint64_t*)data);
	data += 8;

	_pointer = *((uint32_t*)data);
	data += 4;

	_crn1 = *((uint64_t*)data);
	data += 8;

	_crn2 = *((uint64_t*)data);
	data += 8;

	aitf_info = AITF_identity(data, size-27);
}

void AITF_packet::serialize(uint8_t *data, uint32_t size) const{
    *data = packet_type();
    data += 1;

    *((uint64_t*)data) = nonce1();
    data += 8;

    *((uint64_t*)data) = nonce2();
    data += 8;

    *((uint32_t*)data) = pointer();
    data += 4;

    *((uint64_t*)data) = crn1();
    data += 8;

    *((uint64_t*)data) = crn2();
    data += 8;

    identity().serialize(data, size - 27);
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

uint32_t AITF_packet::pointer() const{
	return _pointer;
}

uint64_t AITF_packet::crn1() const{
	return _crn1;
}

uint64_t AITF_packet::crn2() const{
	return _crn2;
}

void AITF_packet::set_crn1(uint64_t c1){
	_crn1 = c1;
}

void AITF_packet::set_crn2(uint64_t c2){
	_crn2 = c2;
}

AITF_identity AITF_packet::identity() const{
	return aitf_info;
}

int AITF_packet::packet_size(){
	return sizeof(packet_type()) + sizeof(nonce1()) + sizeof(nonce2()) + sizeof(pointer()) + sizeof(crn1()) + sizeof(crn2()) + identity().packet_size();
}

string AITF_packet::to_string(){
	stringstream data;
	data << "\nPT: " << packet_type() << " N1: " << nonce1() << " N2: " << nonce2() << " P: " << pointer() << " C1: " << crn1() << " C2: " << crn2() << " ID: " << identity().to_string();
	return data.str();
}