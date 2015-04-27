#pragma once
#include <tins/tins.h>
#include <cassert>
#include "RRFilter.h"
#include <sstream> 

using namespace Tins;
using namespace std;

class AITF_identity{
public:
	AITF_identity();
	AITF_identity(vector<RRFilter> rfilters, IP::address_type victim, uint32_t size);
	AITF_identity(const uint8_t *data, uint32_t size);

	void addRRFilter(RRFilter rfil);
	void serialize(uint8_t *data, uint32_t size) const;

	vector<RRFilter> filters() const;
	IP::address_type victim() const;
	
	uint32_t size() const;

	int packet_size();

	string to_string();

	bool operator == ( const AITF_identity& i) const;
	bool operator < ( const AITF_identity& other) const;

private:
	IP::address_type _victim;
	uint32_t _size;
	vector<RRFilter> _filters;
	

};