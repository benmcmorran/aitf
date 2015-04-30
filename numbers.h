#pragma once

#include <tins/tins.h>

uint64_t generate_key();
uint64_t hash_for_destination(IP::address_type address, int steps);