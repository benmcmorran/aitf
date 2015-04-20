#include "RR.h"

RR::RR(const uint8_t* data, uint32_t size) : route_vec() {
    assert(size >= 3);

    int position = 0;
    protocol = data[position];
    position += 1;

    uint8_t count = data[position];
    position += 1;

    capacity = data[position];
    position += 1;
    assert(size - position >= route_capacity() * 20);

    for (int i = 0; i < count; i++) {
        route_vec.push_back(RREntry(&data[position], 20));
        position += 20;
    }

    position += 20 * (capacity - count);

    payload_vec = std::vector<uint8_t>(data + position, data + size);
}

RR::RR(uint8_t protocol, uint8_t capacity, const uint8_t* payload, uint32_t size) :
    protocol(protocol), capacity(capacity), route_vec() {
    payload_vec = std::vector<uint8_t>(payload, payload + size);
}

RR *RR::clone() const {
    return new RR(*this);
}

uint32_t RR::header_size() const {
    return 3 + route_capacity() * 20 + payload().size();
}
    
PDU::PDUType RR::pdu_type() const {
    return pdu_flag;
}

void RR::write_serialization(uint8_t *data, uint32_t size, const PDU *parent) { 
    assert(size >= header_size());
    assert(route_capacity() >= route().size());

    *data = original_protocol();
    data += 1;

    *data = (uint8_t)route().size();
    data += 1;

    *data = route_capacity();
    data += 1;

    for (int i = 0; i < route().size(); i++) {
        route().at(i).serialize(data, 20);
        data += 20;
    }

    data += (route_capacity() - route().size()) * 20;
    std::copy(payload().begin(), payload().end(), data);
}
    
uint8_t RR::original_protocol() const {
    return protocol;
}

uint8_t RR::route_capacity() const {
    return capacity;
}

std::vector<RREntry> &RR::route() {
    return route_vec;
}

const std::vector<uint8_t> &RR::payload() const {
    return payload_vec;
}

const PDU::PDUType RR::pdu_flag = PDU::USER_DEFINED_PDU;

// Uncomment to test the RR PDU
/*
#include <iostream>
#include <iomanip>
using namespace std;

int main() {
    uint8_t test[] = {
        0x32, 0x02, 0x05,
        0x12, 0x34, 0x56, 0x78, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xff, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xff,
        0x9A, 0xBC, 0xDE, 0xF0, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xff, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe
    };

    uint8_t buffer[111];

    RR rr = RR(test, sizeof(test));
    cout << showbase << hex;
    cout << "Original protocol " << (int)rr.original_protocol() << endl;
    cout << "Route capacity " << (int)rr.route_capacity() << endl;
    cout << "Route" << endl;

    for (int i = 0; i < rr.route().size(); i++) {
        RREntry entry = rr.route().at(i);
        cout << noshowbase << dec << entry.address() << showbase << hex << " " << entry.random_number_1() << " " << entry.random_number_2() << endl;
    }

    RREntry entry = RREntry(IP::address_type("3.5.7.9"), 5, 6);
    rr.route().push_back(entry);
    rr.write_serialization(test, 111, 0);

    for (int i = 0; i < rr.header_size(); i++) {
        cout << noshowbase << setw(2) << (int)test[i];
    }
}
*/