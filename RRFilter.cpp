#include "RRFilter.h"

RRFilter::RRFilter(uint8_t mtype, RREntry data){
	_match_type = mtype;
	_address = data.address();
	_random_number_1 = data.random_number_1();
	_random_number_2 = data.random_number_2();
}

RRFilter::RRFilter(uint8_t mtype, IP::address_type addr, uint64_t ran1, uint64_t ran2){
	_match_type = mtype;
	_address = addr;
	_random_number_1 = ran1;
	_random_number_2 = ran2;
}

RRFilter::RRFilter(const uint8_t* data, uint32_t size){
	_match_type = *data;
	data += 1;

	_address = IP::address_type(*(uint32_t*) data);
	data += 4;

	_random_number_1 = (*(uint64_t*) data);
	data += 8;

	_random_number_2 = (*(uint64_t*)data);
}

void RRFilter::serialize(uint8_t *data, uint32_t size) const{
	assert(size >= 21);

	*data = match_type();
	data += 1;

	*(uint32_t*)data = (uint32_t)address();
	data += 4;
	*(uint64_t*)data = random_number_1();
	data += 8;
	*(uint64_t*)data = random_number_2();
}

const IP::address_type RRFilter::address() const {
	return _address;
}

uint8_t RRFilter::match_type() const{
	return _match_type;
}
	
uint64_t RRFilter::random_number_1() const{
	return _random_number_1;
}
	
uint64_t RRFilter::random_number_2() const{
	return _random_number_2;
}

void RRFilter::set_address(IP::address_type addr) {
	_address = addr;
}

void RRFilter::set_random_number_1(uint64_t r1){
	_random_number_1 = r1;
}

void RRFilter::set_random_number_2(uint64_t r2){
	_random_number_2 = r2;
}

void RRFilter::set_match_type(uint8_t mt){
	_match_type = mt;
}

void RRFilter::set_ttl(uint32_t t){
	_ttl = t;
}

uint32_t RRFilter::ttl(){
	return _ttl;
}

void RRFilter::set_destaddr(IP::address_type addr){
	_destaddr = addr;
}

const IP::address_type RRFilter::destaddr() const{
	return _destaddr;
}

string RRFilter::to_string(){
	stringstream data;
	data << "MT: " << match_type() << " R1: " << random_number_1() << " R2: " << random_number_2() << " ADDR: " << address();
	return data.str();
}

bool RRFilter::operator==(RRFilter i) const{
	if (_address == i.address() && _random_number_1 == i.random_number_1() && _random_number_2 == i.random_number_2()){
		return true;
	}else{
		return false;
	}
}

int RRFilter::match(RREntry entry, IP::address_type addr){
	if (addr == destaddr() && match_type() == 1){
		return 0;
	}

	if (addr == destaddr()){
		if (entry.address() == address()){
			if (match_type() == 0){
				return 0;
			}else{
				if (random_number_1() == entry.random_number_1() || random_number_2() == entry.random_number_1()){
					return 1;
				}else{
					return 0;
				}	
			}
		}else{
			return 2;
		}
	}
	return 2;
}