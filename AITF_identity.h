#pragma once
#include <tins/tins.h>
#include <cassert>
#include "RRFilter.h"

using namespace Tins;
using namespace std;

class AITF_identity{
public:
	AITF_identity(vector<RRFilter> rfilters, IP::address_type victim);
	AITF_identity(const uint8_t *data, uint32_t size);

	void addRRFilter(RRFilter rfil);
	void serialize(uint8_t *data, uint32_t size) const;

	vector<RRFilter> filters();
	IP::address_type victim();
	int pointer();

private:
	IP::address_type _victim;
	vector<RRFilter> _filters;
	int _pointer;

};