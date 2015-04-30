#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>            /* for NF_ACCEPT */

#include <pthread.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <tins/tins.h>
#include <tins/network_interface.h>
#include <iostream>
#include <fstream>

#include "RR.h"
#include "HostMappingReader.h"
#include "HostMapping.h"
#include "AITF_packet.h"
#include "numbers.h"

int intializeAITF(void*);
int block_verdict(RREntry, IP::address_type);
void send_AITF_message(AITF_packet pack, IP::address_type addr);

using namespace Tins;
using namespace std;

typedef enum {
    ROUTER,
    HOST
} Mode;

typedef struct {
    int queue;
    Mode mode;
} nf_data;

bool is_victim = false;
bool last_event_set = false;
struct timeval last_event;
long long event_delay;

bool is_bad = false;
bool is_spoof = false;
HostMapping hosts;

static void print_route(std::vector<RREntry>& route) {
    for (int i = 0; i < route.size(); i++)
        cout << i << " " << route[i].address() << " " << route[i].random_number_1() << " " << route[i].random_number_2() << endl;
}

static void create_rr(IP& ip) {
    //cout << "Creating RR table" << endl;
    std::vector<uint8_t> payload = ip.serialize_inner();
    RR newRR(ip.protocol(), 5, &payload[0], payload.size());
    ip.inner_pdu(newRR);
}

static void strip_rr(IP& ip, const RR& rr) {
    //cout << "Stripping RR table" << endl;
    RawPDU raw = RawPDU(&rr.payload()[0], rr.payload().size());
    ip.inner_pdu(raw);
    ip.protocol(rr.original_protocol());
}

static bool should_intercept(const IP& ip, const RR* rr, AITF_packet *aitf) {
    if (!hosts.isEnabledHost(ip.dst_addr())) return false;

    const UDP *udp = ip.find_pdu<UDP>();
    if (udp != 0) {
        if (udp->dport() == 11467) {
            const RawPDU *raw = udp->find_pdu<RawPDU>();
            *aitf = AITF_packet(&raw->payload()[0], raw->payload().size());
            return true;
        }
        return false;
    }

    if (rr != 0) {
        try {
            UDP udp(&rr->payload()[0], rr->payload().size());
            if (udp.dport() == 11467) {
                const RawPDU *raw = udp.find_pdu<RawPDU>();
                *aitf = AITF_packet(&raw->payload()[0], raw->payload().size());
                return true;
            }
        } catch (malformed_packet e) { }
    }

    return false;
}

static bool is_blocked(const RREntry& entry, const IP::address_type destination) {
    return !is_bad && block_verdict(entry, destination) == NF_DROP;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    Mode mode = ((nf_data*)data)->mode;
    u_int32_t id = ntohl(nfq_get_msg_packet_hdr(nfa)->packet_id);
    unsigned char *packet;
    int size = nfq_get_payload(nfa, &packet);

    std::vector<uint8_t> result;
    u_int32_t verdict = NF_ACCEPT;

    try {
        IP ip = IP(packet, size);
        //cout << ip.src_addr() << " -> " << ip.dst_addr() << endl;
        NetworkInterface interface(ip.dst_addr());
        IP::address_type interface_addr = interface.addresses().ip_addr;

        RR *rr = ip.find_pdu<RR>();

        if (mode == ROUTER) {
            if (rr != 0) {
                //cout << "Adding to existing RR" << endl;
            } else {
                create_rr(ip);
                rr = ip.find_pdu<RR>();
                if (is_spoof && ip.src_addr() == IP::address_type("192.168.30.10")) {
                    rr->route().push_back(RREntry(IP::address_type("192.168.100.20"), 42, 42));
                }
            }

            // TODO Figure out what the magic numbers are for the source address
            RREntry last_hop(ip.src_addr(), 0x0, 0x0);
            if (rr != 0 && rr->route().size() >= 1)
                last_hop = rr->route().back();

            AITF_packet aitf;
            if (should_intercept(ip, rr, &aitf)) {
                //cout << "Intercepting packet" << endl;
                send_AITF_message(aitf, IP::address_type("192.168.10.100"));
                verdict = NF_DROP;
            }
            else if (is_blocked(last_hop, ip.dst_addr())) {
                //cout << "Packet blocked" << endl;
                verdict = NF_DROP;
            } else if (hosts.isLegacyHost(ip.dst_addr())) {
                //cout << "Legacy host detected" << endl;
                if (rr != 0) {
                    //print_route(rr->route());
                    strip_rr(ip, *rr);
                } else {
                    //cout << "No RR table present" << endl;
                }
            } else {
                NetworkInterface interface(ip.dst_addr());
                rr->route().push_back(RREntry(interface_addr, hash_for_destination(ip.dst_addr(), 0), hash_for_destination(ip.dst_addr(), 1)));

                if (rr->route().size() > rr->route_capacity()) {
                    //cout << "RR table filled. Dropping packet." << endl;
                    verdict = NF_DROP;
                } //else print_route(rr->route());
            }
        } else if (mode == HOST) {
            if (rr != 0) {
                // Check if this is a bad packet
                // TODO don't hard code attacker ip addresses
                bool is_bad = false;

                try {
                    UDP udp(&rr->payload()[0], rr->payload().size());
                    RawPDU* raw = udp.find_pdu<RawPDU>();
                    if (raw != 0) {
                        is_bad = raw->payload()[0] == 1;
                    }
                } catch (malformed_packet e) { }


                if (is_bad && is_victim) {
                    if (!last_event_set) {
                        printf("Attack detected\n");
                        gettimeofday(&last_event, NULL);
                        last_event_set = true;
                        event_delay = 500000;
                    } else {
                        struct timeval now;
                        gettimeofday(&now, NULL);
                        if ((now.tv_sec - last_event.tv_sec) * 1000000 + now.tv_usec - last_event.tv_usec > event_delay) {
                            printf("Enforce sent\n");
                            print_route(rr->route());

                            vector<RRFilter> filters;
                            filters.push_back(RRFilter(0, ip.src_addr(), 0x0, 0x0));
                            for (int i = 0; i < rr->route().size(); i++) {
                                const RREntry& entry = rr->route().at(i);
                                filters.push_back(RRFilter(0, entry.address(), entry.random_number_1(), entry.random_number_2()));
                            }

                            AITF_packet enforce(0, 0, 0, 1, filters, IP::address_type("192.168.10.10"), filters.size());
                            send_AITF_message(enforce, IP::address_type("192.168.10.100"));

                            last_event = now;
                            event_delay = 10000000;
                        }
                    }
                }

                //print_route(rr->route());
                strip_rr(ip, *rr);
            } else {
                //cout << "No RR table present" << endl;
            }
        }

        result = ip.serialize();
        //cout << endl;

    } catch (malformed_packet e) {
        cout << "malformed packet " << e.what() << endl;
    }
    
    return nfq_set_verdict(qh, id, verdict,
        verdict == NF_DROP ? 0 : result.size(),
        verdict == NF_DROP ? 0 : &result[0]);
}

void fail(const char* msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

void usage() {
    fail("Usage: rr [--host] [--list hostsfile] [--queue number]");
}

void run(nf_data* data) {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    int queue = data->queue;

    h = nfq_open();
    if (!h) fail("error during nfq_open()");
    if (nfq_unbind_pf(h, AF_INET) < 0) fail("error during nfq_unbind_pf()");
    if (nfq_bind_pf(h, AF_INET) < 0) fail("error during nfq_bind_pf()");

    qh = nfq_create_queue(h, queue, &cb, (void*)data);
    if (!qh) fail("error during nfq_create_queue()");

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) fail("can't set packet_copy mode");

    fd = nfq_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)
        nfq_handle_packet(h, buf, rv);

    nfq_destroy_queue(qh);

#ifdef INSANE
        /* normally, applications SHOULD NOT issue this command, since
         * it detaches other programs/sockets from AF_INET, too ! */
        nfq_unbind_pf(h, AF_INET);
#endif

    nfq_close(h);
}

int main(int argc, char **argv)
{
    // Configure libtins to recognize the RR protocol
    // RR uses the IP protocol number 253 reserved for testing
    Allocators::register_allocator<IP, RR>(253);

    if (argc >= 2) {
        for (int i = 0; i < argc; i++) {
            if (strcmp(argv[i], "--list") == 0) {
                if (i + 1 >= argc) usage();
                try {
                    hosts = HostMappingReader::read_from_path(argv[i + 1]);
                    i++;
                } catch (const AITFException& e) {
                    fail("Could not read hosts file");
                }
            } else if (strcmp(argv[i], "--bad") == 0) {
                is_bad = true;
            } else if (strcmp(argv[i], "--victim") == 0) {
                is_victim = true;
            } else if (strcmp(argv[i], "--spoof") == 0) {
                is_spoof = true;
            }
        }
    }

    intializeAITF(NULL);

    nf_data thread1data = { .queue = 0, .mode = ROUTER };
    nf_data thread2data = { .queue = 1, .mode = HOST };
    pthread_t helper1, helper2;
    pthread_create(&helper1, NULL, (void*(*)(void*))run, &thread1data);
    pthread_create(&helper2, NULL, (void*(*)(void*))run, &thread2data);

    pthread_join(helper1, NULL);

    exit(0);
}