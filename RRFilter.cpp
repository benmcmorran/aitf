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

int RRFilter::match(IP::address_type addr){
	if ((uint32_t)addr == (uint32_t)address()){
		return 1;
	}else{
		return 0;
	}
}