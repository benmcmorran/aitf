#pragma once
#include <tins/tins.h>
#include <cassert>
#include "RREntry.h"
#include "AITF_identity.h"

using namespace Tins;
using namespace std;

class AITF_packet{
public:
	AITF_packet(uint8_t ptype, uint64_t nonce1, uint64_t nonce2, uint32_t size, uint32_t pointer, vector<RRFilter> rfilters, IP::address_type dest_addr);
	AITF_packet(uint8_t ptype, uint64_t nonce1, uint64_t nonce2, IP::address_type dest_addr);
	AITF_packet(const uint8_t *data, uint32_t size);

	void addRRFilter(RRFilter rfil);
	void serialize(uint8_t *data, uint32_t size) const;
	AITF_identity identity();

	uint8_t packet_type();
	uint64_t nonce1();
	uint64_t nonce2();
	uint32_t size();

private:
	uint8_t _packet_type;
	uint64_t _nonce1;
	uint64_t _nonce2;
	uint32_t _size;
	AITF_identity aitf_info;

};