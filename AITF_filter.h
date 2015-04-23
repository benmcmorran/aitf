#pragma once
#include <tins/tins.h>
#include <cassert>
#include "RREntry.h"

using namespace Tins;

class AITF_filter {
public:
	AITF_filter(IP::address_type address, uint64_t random_number_1, uint64_t random_number_2);

	// Used to validate incomming packets (READ ONLY)
	int isValidPacket(RRentry flow);

	// Used to manipulate the AITF filter (WRITE AND READ)
	void addFilter(RRFilter filter);
	void removeFilter(RRFilter filter);

}