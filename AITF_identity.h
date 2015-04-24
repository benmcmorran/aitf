#pragma once
#include <tins/tins.h>
#include <cassert>
#include "RRFilter.h"

using namespace Tins;
using namespace std;

class AITF_identity{
public:
	AITF_identity();
	AITF_identity(vector<RRFilter> rfilters, IP::address_type victim, uint32_t pointer);
	AITF_identity(const uint8_t *data, uint32_t size);

	void addRRFilter(RRFilter rfil);
	void serialize(uint8_t *data, uint32_t size) const;

	vector<RRFilter> filters() const;
	IP::address_type victim() const;
	uint32_t pointer() const;

private:
	IP::address_type _victim;
	vector<RRFilter> _filters;
	uint32_t _pointer;

};