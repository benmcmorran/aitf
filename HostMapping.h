#pragma once
#include <tins/tins.h>

using namespace Tins;

class HostMapping {
public:
	HostMapping();
	void addLegacyHost(IP::address_type address);
	void addEnabledHost(IP::address_type address);
	bool isLegacyHost(IP::address_type address);
	bool isEnabledHost(IP::address_type address);

private:
	std::set<IP::address_type> legacy_hosts;
	std::set<IP::address_type> enabled_hosts;
};
