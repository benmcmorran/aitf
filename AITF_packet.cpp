#include "AITF_packet.h"

AITF_packet::AITF_packet(uint8_t ptype, uint64_t nonce1, uint64_t nonce2, uint32_t size, vector<RRFilter> rfilters):
	packet_type(ptype), nonce1(nonce1), nonce2(nonce2), size(size), filters(rfilters){}


AITF_packet::AITF_packet(uint8_t ptype, uint64_t nonce1, uint64_t nonce2, uint32_t size):
	packet_type(ptype), nonce1(nonce1), nonce2(nonce2), size(size), filters(){}

AITF_packet::AITF_packet(const uint8_t *data, uint32_t size) : filters(){

	packet_type = ntohll(*((uint8_t*)data));
	data += 1;

	nonce1 = ntohll(*((uint64_t*)data));
	data += 8;

	nonce2 = ntohll(*((uint64_t*)data));
	data += 8;

	size = ntohll(*((uint32_t*)data));
	data += 4;

	for (int i = 0; i < size; i++) {
        filters.push_back(RRFilter(data, sizeof(RRFilter));
        position += sizeof(RRFilter);
    }
}