#include "HostMappingReader.h"

HostMapping HostMappingReader::read_from_path(const std::string& path) {
	std::ifstream file(path.c_str());

	if (file.fail()) throw AITFException("Hosts file could not be opened");

	HostMapping mapping;

	std::string type;
	std::string ip_text;
	while (file >> type >> ip_text) {
		IP::address_type ip(ip_text);
		if (type == "e")
			mapping.addEnabledHost(ip);
		else if (type == "l")
			mapping.addLegacyHost(ip);
		else
			throw new AITFException("Invalid host type");
	}

	return mapping;
}
