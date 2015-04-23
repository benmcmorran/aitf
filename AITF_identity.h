#pragma once
#include <tins/tins.h>
#include <cassert>
#include "RREntry.h"

using namespace Tins;

class AITF_packet{
public:
	AITF_identity(vector<RRFilter> rfilters, uint32_t dest_addr);
	AITF_packet(uint32_t dest_addr);
	AITF_packet(const uint8_t *data, uint32_t size);

	void addRRFilter(RRFilter rfil);
	void serialize(uint8_t *data, uint32_t size) const;
	

private:
	uint32_t dest_addr;
	vector<RRFilter> filters;

}