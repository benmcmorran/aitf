#pragma once
#include <tins/tins.h>
#include <cassert>
#include "RREntry.h"

class RR : public PDU {
public:
    static const PDU::PDUType pdu_flag;

    RR(const uint8_t* data, uint32_t size);
    RR(uint8_t protocol, uint8_t capacity, const uint8_t* payload, uint32_t size);
    RR *clone() const;
    uint32_t header_size() const;
    PDUType pdu_type() const;
    
    void write_serialization(uint8_t *data, uint32_t sz, const PDU *parent);
    
    uint8_t original_protocol() const;
    uint8_t route_capacity() const;
    std::vector<RREntry> &route();
    const std::vector<uint8_t> &payload() const;

private:
    uint8_t protocol;
    uint8_t capacity;
    std::vector<RREntry> route_vec;
    std::vector<uint8_t> payload_vec;
};
