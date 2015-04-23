#pragma once
#include <tins/tins.h>
#include <cassert>
#include "RREntry.h"

using namespace Tins;

class AITF_packet{
public:
	AITF_packet(uint8_t ptype, uint64_t nonce1, uint64_t nonce2, uint32_t size, vector<RRFilter> rfilters);
	AITF_packet(uint8_t ptype, uint64_t nonce1, uint64_t nonce2, uint32_t size);
	AITF_packet(const uint8_t *data, uint32_t size);

	void addRRFilter(RRFilter rfil);
	void serialize(uint8_t *data, uint32_t size) const;

private:
	uint8_t packet_type;
	uint64_t nonce1;
	uint64_t nonce2;
	uint32_t size;
	vector<RRFilter> filters;

}