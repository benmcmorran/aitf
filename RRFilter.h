#pragma once
#include <tins/tins.h>
#include <cassert>
#include "RREntry.h"

using namespace Tins;

class RRFilter{
public:
	RRFilter(uint8_t mtype, RREntry data);
	RRFilter(uint8_t mtype, IP::address_type addr, uint64_t ran1, uint64_t ran2);

	const IP::address_type address() const;
	uint8_t match_type() const;
	uint64_t random_number_1() const;
	uint64_t random_number_2() const;

	int match(RREntry entry);

private:
	uint8_t _match_type;
	IP::address_type _address;
	uint64_t _random_number_1;
	uint64_t _random_number_2;
};