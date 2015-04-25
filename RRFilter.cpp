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

void RRFilter::set_random_number_1(uint64_t r1){
	_random_number_1 = r1;
}

void RRFilter::set_random_number_2(uint64_t r2){
	_random_number_2 = r2;
}

void RRFilter::set_match_type(uint8_t mt){
	_match_type = mt;
}

bool RRFilter::operator==(RRFilter i) const{
	if (_address == i.address() && _random_number_1 == i.random_number_1() && _random_number_2 == i.random_number_2()){
		return true;
	}else{
		return false;
	}
}

int RRFilter::match(RREntry entry){
	if (entry.address() == address()){
		return 1;
	}else{
		return 0;
	}
}