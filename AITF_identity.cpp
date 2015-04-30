#include "AITF_identity.h"

AITF_identity::AITF_identity():
	_victim(), _filters(), _size(){}

AITF_identity::AITF_identity(vector<RRFilter> rfilters, IP::address_type victim, uint32_t size):
	_victim(victim), _filters(rfilters), _size(size){}

AITF_identity::AITF_identity(const uint8_t *data, uint32_t size){
	_victim = IP::address_type(*(uint32_t*) data);
	data += 4;

	_size = *((uint32_t*)data);
	data += 4;

	for (int i =0; i < _size; i++){
		_filters.push_back(RRFilter(data, 21));
		data += 21;
	}
}

void AITF_identity::serialize(uint8_t *data, uint32_t size) const{
	*(uint32_t*)data = victim();
	data += 4;

	*(uint32_t*)data = this->size();
	data += 4;

	for (int i = 0; i < filters().size(); i++) {
        filters().at(i).serialize(data, 21);
        data += 21;
    }
}

vector<RRFilter> AITF_identity::filters() const{
	return _filters;
}

IP::address_type AITF_identity::victim() const{
	return _victim;
}

uint32_t AITF_identity::size() const{
	return _size;
}

int AITF_identity::packet_size(){
	return sizeof(victim()) + sizeof(size()) + 21 * size();
}

bool AITF_identity::operator==(const AITF_identity& i) const{
	if (_victim == i.victim() && _filters==i.filters()){
		return true;
	}else{
		return false;
	}
}

bool AITF_identity::operator < ( const AITF_identity& other) const{
	return _victim + _filters[0].address() < other.victim() + other.filters()[0].address();
}

string AITF_identity::to_string(){
	stringstream data;
	data << " V: " << victim();
	data << " S: " << size();
	data << "RRFTABLE: \n";
	for (int i = 0; i < filters().size(); i++){
		data << filters().at(i).to_string() << "\n";
	}
	return data.str();
}