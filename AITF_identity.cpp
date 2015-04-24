#include "AITF_identity.h"

AITF_identity::AITF_identity():
	_victim(), _filters(), _pointer(){}

AITF_identity::AITF_identity(vector<RRFilter> rfilters, IP::address_type victim, uint32_t pointer):
	_victim(victim), _filters(rfilters), _pointer(pointer){}

AITF_identity::AITF_identity(const uint8_t *data, uint32_t size){
	int offset = 0;
	_victim = IP::address_type(*(uint32_t*) data);
}


vector<RRFilter> AITF_identity::filters(){
	return _filters;
}

IP::address_type AITF_identity::victim(){
	return _victim;
}

uint32_t AITF_identity::pointer(){
	return _pointer;
}