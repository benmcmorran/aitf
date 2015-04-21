#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>            /* for NF_ACCEPT */

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <tins/tins.h>
#include <tins/network_interface.h>
#include <iostream>
#include <fstream>

#include "RR.h"
#include "HostMappingReader.h"
#include "HostMapping.h"

using namespace Tins;
using namespace std;

typedef enum {
    ROUTER,
    HOST
} Mode;

Mode mode = ROUTER;
HostMapping hosts;

static void print_route(std::vector<RREntry>& route) {
    for (int i = 0; i < route.size(); i++)
        cout << i << " " << route[i].address() << endl;
}

static void create_rr(IP& ip) {
    cout << "Creating RR table" << endl;
    std::vector<uint8_t> payload = ip.serialize_inner();
    RR newRR(ip.protocol(), 5, &payload[0], payload.size());
    ip.inner_pdu(newRR);
}

static void strip_rr(IP& ip, const RR& rr) {
    cout << "Stripping RR table" << endl;
    RawPDU raw = RawPDU(&rr.payload()[0], rr.payload().size());
    ip.inner_pdu(raw);
    ip.protocol(rr.original_protocol());
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    u_int32_t id = ntohl(nfq_get_msg_packet_hdr(nfa)->packet_id);
    unsigned char *packet;
    int size = nfq_get_payload(nfa, &packet);

    std::vector<uint8_t> result;
    u_int32_t verdict = NF_ACCEPT;

    try {
        IP ip = IP(packet, size);
        cout << ip.src_addr() << " -> " << ip.dst_addr() << endl;

        RR *rr = ip.find_pdu<RR>();

        if (mode == ROUTER) {
            if (hosts.isLegacyHost(ip.dst_addr())) {
                cout << "Legacy host detected" << endl;
                if (rr != 0) {
                    print_route(rr->route());
                    strip_rr(ip, *rr);
                } else {
                    cout << "No RR table present" << endl;
                }
            } else {
                if (rr != 0) {
                    cout << "Adding to existing RR" << endl;
                } else {
                    create_rr(ip);
                    rr = ip.find_pdu<RR>();
                }

                NetworkInterface interface(ip.dst_addr());
                rr->route().push_back(RREntry(interface.addresses().ip_addr, 0xaaaaaaaaaaaaaaaa, 0xbbbbbbbbbbbbbbbb));

                if (rr->route().size() > rr->route_capacity()) {
                    cout << "RR table filled. Dropping packet." << endl;
                    verdict = NF_DROP;
                } else print_route(rr->route());
            }
        } else if (mode == HOST) {
            if (rr != 0) {
                print_route(rr->route());
                strip_rr(ip, *rr);
            } else {
                cout << "No RR table present" << endl;
            }
        }

        result = ip.serialize();
        cout << endl;

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
    fail("Usage: rr [--host] [--list hostsfile]");
}

int main(int argc, char **argv)
{
    // Configure libtins to recognize the RR protocol
    // RR uses the IP protocol number 253 reserved for testing
    Allocators::register_allocator<IP, RR>(253);

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    if (argc >= 2) {
        for (int i = 0; i < argc; i++) {
            if (strcmp(argv[i], "--host") == 0)
                mode = HOST;
            else if (strcmp(argv[i], "--list") == 0) {
                if (i + 1 >= argc) usage();
                try {
                    hosts = HostMappingReader::read_from_path(argv[i + 1]);
                    i++;
                } catch (const AITFException& e) {
                    fail("Could not read hosts file");
                }
            }
        }
    }

    if (mode == HOST)
        cout << "Running in host mode" << endl;
    else if (mode == ROUTER)
        cout << "Running in router mode" << endl;


    h = nfq_open();
    if (!h) fail("error during nfq_open()");
    if (nfq_unbind_pf(h, AF_INET) < 0) fail("error during nfq_unbind_pf()");
    if (nfq_bind_pf(h, AF_INET) < 0) fail("error during nfq_bind_pf()");

    qh = nfq_create_queue(h,  0, &cb, NULL);
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
    exit(0);
}