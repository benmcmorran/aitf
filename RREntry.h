#pragma once
#include <tins/tins.h>
#include <cassert>
#include "Utils.h"

using namespace Tins;

class RREntry {
public:
	RREntry(IP::address_type address, uint64_t random_number_1, uint64_t random_number_2);
	RREntry(const uint8_t *data, uint32_t size);
	void serialize(uint8_t *data, uint32_t size) const;

	const IP::address_type address() const;
	uint64_t random_number_1() const;
	uint64_t random_number_2() const;

private:
	IP::address_type _address;
	uint64_t _random_number_1;
	uint64_t _random_number_2;
};