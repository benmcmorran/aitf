#pragma once
#include <iostream>
#include <fstream>
#include <string>

#include <tins/tins.h>

#include "HostMapping.h"
#include "AITFException.h"

using namespace Tins;

class HostMappingReader {
public:
		static HostMapping read_from_path(const std::string& path);
};