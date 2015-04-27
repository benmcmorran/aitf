#pragma once
#include <tins/tins.h>
#include <cassert>
#include <string.h>
#include <sstream> 
#include "RREntry.h"

using namespace Tins;
using namespace std;

class RRFilter{
public:
	RRFilter(uint8_t mtype, RREntry data);
	RRFilter(uint8_t mtype, IP::address_type addr, uint64_t ran1, uint64_t ran2);
	RRFilter(const uint8_t* data, uint32_t size);

	void serialize(uint8_t *data, uint32_t size) const;

	const IP::address_type address() const;
	uint8_t match_type() const;
	uint64_t random_number_1() const;
	uint64_t random_number_2() const;

	void set_random_number_1(uint64_t n1);
	void set_random_number_2(uint64_t n2);
	void set_match_type(uint8_t mt);
	int match(RREntry entry, IP::address_type addr);

	void set_ttl(uint32_t t);
	uint32_t ttl();

	string to_string();
	bool operator==(RRFilter i) const;

private:
	uint8_t _match_type;
	IP::address_type _address;
	uint64_t _random_number_1;
	uint64_t _random_number_2;
	uint32_t _ttl;
};