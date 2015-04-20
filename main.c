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

#include "RR.h"

using namespace Tins;
using namespace std;

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
        if (rr != 0) {
            cout << "Adding to existing RR" << endl;
        } else {
            cout << "Creating RR table" << endl;
            std::vector<uint8_t> payload = ip.serialize_inner();
            RR newRR(ip.protocol(), 5, &payload[0], payload.size());
            ip.inner_pdu(newRR);
            rr = ip.find_pdu<RR>();
        }

        NetworkInterface interface(ip.dst_addr());
        rr->route().push_back(RREntry(interface.addresses().ip_addr, 0xaaaaaaaaaaaaaaaa, 0xbbbbbbbbbbbbbbbb));

        if (rr->route().size() > rr->route_capacity()) {
            cout << "RR table filled. Dropping packet." << endl;
            verdict = NF_DROP;
        } else {
            for (int i = 0; i < rr->route().size(); i++)
                cout << i << " " << rr->route()[i].address() << endl;

            result = ip.serialize();
        }

        cout << endl;

        /*
        for (int i = 0; i < size; i++) printf("%02x", packet[i]);
        printf("\n\n");

        // Insert and remove the shim
        std::vector<uint8_t> payload = ip.serialize_inner();

        RR rr = RR(ip.protocol(), 5, &payload[0], payload.size());
        result = rr.serialize();

        for (int i = 0; i < result.size(); i++) printf("%02x", result.at(i));
        printf("\n\n");

        ip.inner_pdu(rr);
        result = ip.serialize();

        for (int i = 0; i < result.size(); i++) printf("%02x", result.at(i));
        printf("\n\n");

        IP newIP = IP(&result[0], result.size());
        RR *rrptr = newIP.find_pdu<RR>();
        RawPDU raw = RawPDU(&rrptr->payload()[0], rrptr->payload().size());
        newIP.inner_pdu(raw);
        newIP.protocol(rrptr->original_protocol());

        result = newIP.serialize();

        for (int i = 0; i < result.size(); i++) printf("%02x", result.at(i));
        printf("\n\n");
        */
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