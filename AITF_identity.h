#pragma once
#include <tins/tins.h>
#include <cassert>
#include "RREntry.h"

using namespace Tins;

class AITF_identity{
public:
	AITF_identity(vector<RRFilter> rfilters, IP::address_type victim);
	AITF_identity(const uint8_t *data, uint32_t size);

	void addRRFilter(RRFilter rfil);
	void serialize(uint8_t *data, uint32_t size) const;

	vector<RRFilter> filters();
	IP::address_type victim();
	

private:
	IP::address_type victim;
	vector<RRFilter> filters;

}