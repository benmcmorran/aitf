#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>            /* for NF_ACCEPT */

#include <libnetfilter_queue/libnetfilter_queue.h>

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
        int id = 0;
        struct nfqnl_msg_packet_hdr *ph;
        struct nfqnl_msg_packet_hw *hwph;
        u_int32_t mark,ifi; 
        int ret;
        unsigned char *data;

        ph = nfq_get_msg_packet_hdr(tb);
        if (ph) {
                id = ntohl(ph->packet_id);
                printf("hw_protocol=0x%04x hook=%u id=%u ",
                        ntohs(ph->hw_protocol), ph->hook, id);
        }

        hwph = nfq_get_packet_hw(tb);
        if (hwph) {
                int i, hlen = ntohs(hwph->hw_addrlen);

                printf("hw_src_addr=");
                for (i = 0; i < hlen-1; i++)
                        printf("%02x:", hwph->hw_addr[i]);
                printf("%02x ", hwph->hw_addr[hlen-1]);
        }

        mark = nfq_get_nfmark(tb);
        if (mark)
                printf("mark=%u ", mark);

        ifi = nfq_get_indev(tb);
        if (ifi)
                printf("indev=%u ", ifi);

        ifi = nfq_get_outdev(tb);
        if (ifi)
                printf("outdev=%u ", ifi);
        ifi = nfq_get_physindev(tb);
        if (ifi)
                printf("physindev=%u ", ifi);

        ifi = nfq_get_physoutdev(tb);
        if (ifi)
                printf("physoutdev=%u ", ifi);

        ret = nfq_get_payload(tb, &data);
        if (ret >= 0)
                printf("payload_len=%d ", ret);

        fputc('\n', stdout);

        return id;
}



static int add_RR_route(){
        return 0;
}

static int add_RR_shim(){
        return 0;
}        


struct pkt_buff {
    uint8_t *mac_header;
    uint8_t *network_header;
    uint8_t *transport_header;

    uint8_t *head;
    uint8_t *data;
    uint8_t *tail;

    uint32_t len;
    uint32_t data_len;

    int    mangled;
} pkt_buff;

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{

        u_int32_t id = print_pkt(nfa);
        printf("entering callback\n");

        unsigned char * payload;
        int size;
        size = nfq_get_payload(nfa, &payload);

        size_t extra = 40;

        struct pkt_buff* test;
        test = pktb_alloc(AF_INET, payload, size, extra);

        !size ??!??! printf("error!\n");

        int protocol = *(test->network_header+9);

        int version = *(test->network_header)>>4;
        int iphl = *(test->network_header) & 0x0F;
        int source = *((uint32_t*)(test->network_header + 12));
        int dest = *((uint32_t*)(test->network_header + 16));

        unsigned char bytes[4];
        bytes[0] = source & 0xFF;
        bytes[1] = (source >> 8) & 0xFF;
        bytes[2] = (source >> 16) & 0xFF;
        bytes[3] = (source >> 24) & 0xFF;   
        printf("SOURCE: %d.%d.%d.%d\n", bytes[0], bytes[1], bytes[2], bytes[3]);  

        unsigned char bytes1[4];
        bytes1[0] = dest & 0xFF;
        bytes1[1] = (dest >> 8) & 0xFF;
        bytes1[2] = (dest >> 16) & 0xFF;
        bytes1[3] = (dest >> 24) & 0xFF;   
        printf("DEST: %d.%d.%d.%d\n", bytes1[0], bytes1[1], bytes1[2], bytes1[3]);  

        printf("IPHL: %d \n\n", iphl);
        printf("VERSION: %d \n\n", version);
        printf("PROTOCOL: %d \n\n",protocol);

        printf("%d \n\n", test->network_header);

        printf("%d \n\n", test->mac_header);

        printf("%d \n\n", test->transport_header);

        int x;
        for (x = 0; x < 100; x++){
          printf("%x", payload[x]);
        }
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
        struct nfq_handle *h;
        struct nfq_q_handle *qh;
        struct nfnl_handle *nh;
        int fd;
        int rv;
        char buf[4096] __attribute__ ((aligned));

        printf("opening library handle\n");
        h = nfq_open();
        if (!h) {
                fprintf(stderr, "error during nfq_open()\n");
                exit(1);
        }

        printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
        if (nfq_unbind_pf(h, AF_INET) < 0) {
                fprintf(stderr, "error during nfq_unbind_pf()\n");
                exit(1);
        }

        printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
        if (nfq_bind_pf(h, AF_INET) < 0) {
                fprintf(stderr, "error during nfq_bind_pf()\n");
                exit(1);
        }

        printf("binding this socket to queue '0'\n");
        qh = nfq_create_queue(h,  0, &cb, NULL);
        if (!qh) {
                fprintf(stderr, "error during nfq_create_queue()\n");
                exit(1);
        }

        printf("setting copy_packet mode\n");
        if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
                fprintf(stderr, "can't set packet_copy mode\n");
                exit(1);
        }

        fd = nfq_fd(h);

        while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
                printf("pkt received\n");
                nfq_handle_packet(h, buf, rv);
        }

        printf("unbinding from queue 0\n");
        nfq_destroy_queue(qh);

#ifdef INSANE
        /* normally, applications SHOULD NOT issue this command, since
         * it detaches other programs/sockets from AF_INET, too ! */
        printf("unbinding from AF_INET\n");
        nfq_unbind_pf(h, AF_INET);
#endif

        printf("closing library handle\n");
        nfq_close(h);

         exit(0);
}