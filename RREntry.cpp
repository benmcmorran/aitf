#include "RREntry.h"

RREntry::RREntry(IP::address_type address, uint64_t random_number_1, uint64_t random_number_2) :
	_address(address), _random_number_1(random_number_1), _random_number_2(random_number_2) { }

RREntry::RREntry(const uint8_t *data, uint32_t size) {
	assert(size >= 20);

	// This constructor expects big-endian order, so no conversion is necessary
	_address = IP::address_type(*(uint32_t*)data);
	data += 4;

	_random_number_1 = ntohll(*(uint64_t*)data);
	data += 8;
	_random_number_2 = ntohll(*(uint64_t*)data);
}

void RREntry::serialize(uint8_t *data, uint32_t size) const {
	assert(size >= 20);

	*(uint32_t*)data = (uint32_t)address();
	data += 4;
	*(uint64_t*)data = htonll(random_number_1());
	data += 8;
	*(uint64_t*)data = htonll(random_number_2());
}

const IP::address_type RREntry::address() const {
	return _address;
}

uint64_t RREntry::random_number_1() const {
	return _random_number_1;
}

uint64_t RREntry::random_number_2() const {
	return _random_number_2;
}