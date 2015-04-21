#include "HostMapping.h"

HostMapping::HostMapping() : legacy_hosts(), enabled_hosts() { }

void HostMapping::addLegacyHost(IP::address_type address) {
	legacy_hosts.insert(address);
}

void HostMapping::addEnabledHost(IP::address_type address) {
	enabled_hosts.insert(address);
}

bool HostMapping::isLegacyHost(IP::address_type address) {
	return legacy_hosts.count(address) == 1;
}

bool HostMapping::isEnabledHost(IP::address_type address) {
	return enabled_hosts.count(address) == 1;
}
