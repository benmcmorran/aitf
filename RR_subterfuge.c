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

typedef struct RR_record{
    uint32_t ipaddr;
    uint64_t rn1;
    uint64_t rn2;
} RR_record;

typedef struct RR_shim {
    uint8_t oproc;
    uint32_t pointer;
    uint32_t size;
    RR_record* table;
} RR_shim;

typedef struct pkt_buff {
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


uint16_t ip_checksum(void* vdata,size_t length) {
    // Cast the data pointer to one that can be indexed.
    char* data=(char*)vdata;

    // Initialise the accumulator.
    uint32_t acc=0xffff;

    size_t i;

    // Handle complete 16-bit blocks.
    for (i=0;i+1<length;i+=2) {
        uint16_t word;
        memcpy(&word,data+i,2);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Handle any partial block at the end of the data.
    if (length&1) {
        uint16_t word=0;
        memcpy(&word,data+length-1,1);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}

static uint8_t* add_RR_route(pkt_buff* opack, uint32_t own_addr, uint32_t* packlen){
        
        RR_shim* rshim = opack->head + ((*(opack->network_header) & 0x0F) * 4);

        if (rshim->pointer >= 8){
            printf("Recieved Route with more than 9 hops. BAD PACKET!");
        }

        RR_record* data = opack->head + ((*(opack->head) & 0x0F) * 4) + sizeof(RR_shim) - sizeof(RR_record*);

        data[rshim->pointer].ipaddr = own_addr;
        data[rshim->pointer].rn1 = (uint64_t)9876;
        data[rshim->pointer].rn2 = (uint64_t)12345;



        rshim->pointer = rshim->pointer+1;

        *packlen = opack->len;

        return opack->head;
}


static uint8_t* remove_RR_route(pkt_buff* opack, uint32_t own_addr, uint32_t* packlen){
    RR_shim* rshim = opack->head + ((*(opack->network_header) & 0x0F) * 4);

    uint8_t* oldpack = opack->head + ((*(opack->network_header) & 0x0F) * 4) + sizeof(RR_shim) - sizeof(RR_record*) + sizeof(RR_record) * rshim->size;

    *packlen = (uint16_t)oldpack+2;

    return oldpack;  
}


static uint8_t* add_RR_shim(pkt_buff* opack, uint32_t own_addr, uint32_t* packlen){


        RR_shim* rshim = (RR_shim*) malloc(sizeof(RR_shim));
        rshim->oproc = *(opack->network_header+9);
        rshim->pointer = 1;
        rshim->size = 8;

        rshim->table = (RR_record*) calloc(sizeof(RR_record),8);
        rshim->table[0].ipaddr = (uint32_t)0x55555555;
        rshim->table[0].rn1 = (uint64_t) 0x11111111111111111;
        rshim->table[0].rn2 = (uint64_t)0x11111111111111111;

        uint8_t* new_buff = (unsigned char*) malloc((*(opack->network_header) & 0x0F) * 4 + opack->len + sizeof(RR_shim) - sizeof(RR_record*) + rshim->size * sizeof(RR_record));
        
        *packlen = (*(opack->network_header) & 0x0F) * 4 + opack->len + sizeof(RR_shim) - sizeof(RR_record*) + rshim->size * sizeof(RR_record);

        memcpy(new_buff, opack->network_header, (*(opack->network_header) & 0x0F) * 4);


        int x;

        printf("NETWORK HEADER: \n\n");
        for(x=0;x<(*(opack->network_header) & 0x0F) * 4; x++){
            printf("%02x",opack->network_header[x]);
        }

        printf("\n\n");

        //Change Protocol Number
        *(new_buff + 9) =  (uint8_t) 253;

        *((uint16_t*)(new_buff + 2)) = (uint16_t) (*(opack->network_header) & 0x0F) * 4 + opack->len + sizeof(RR_shim) - sizeof(RR_record*) + rshim->size * sizeof(RR_record);
        *((uint16_t*)(new_buff + 10)) = (uint16_t) 0;
        *((uint16_t*)(new_buff + 10)) = ip_checksum(new_buff, sizeof(*(opack->network_header) & 0x0F) * 4);


        printf("MODIFIED HEADER: \n\n");
        for (x=0;x< (*(opack->network_header) & 0x0F)*4;x++){
            printf("%02x",new_buff[x]);
        }

        uint8_t* temp_pointer = new_buff + (*(opack->network_header) & 0x0F) * 4;
        memcpy(temp_pointer, rshim, sizeof(RR_shim) - sizeof(RR_record*));
        temp_pointer += sizeof(RR_shim) - sizeof(RR_record*);
        memcpy(temp_pointer, rshim->table, sizeof(RR_record)*rshim->size);
        temp_pointer += sizeof(RR_record)*rshim->size;
        memcpy(temp_pointer, opack->data, opack->len);
        temp_pointer += opack->len;

        free(rshim->table);
        free(rshim);
        return new_buff;
}        


void print_RR_shim(uint8_t* test){

    
    RR_shim* rshim = test + ((*(test) & 0x0F) * 4);


    printf("\n\nRSHIM: ORIGINAL PROTOCOL: %d POINTER: %d SIZE: %d", rshim->oproc, rshim->pointer, rshim->size);
    int x;

    RR_record* data = test + ((*(test) & 0x0F) * 4) + sizeof(RR_shim) - sizeof(RR_record*);
    for (x=0;x < rshim->pointer ; x++){

        printf("\n\nRR_RECORD %d: IP: %d  RN1: %d  RN2: %d \n\n", x, data[x].ipaddr, data[x].rn1, data[x].rn2);
    }
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{

        u_int32_t id = print_pkt(nfa);
        printf("entering callback\n");

        unsigned char * payload;
        int size;
        size = nfq_get_payload(nfa, &payload);

        size_t extra = 0;

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

        printf("%d \n\n", test->len);

        printf("%d \n\n", test->data_len);

        int x;
        for (x = 0; x < 100; x++){
          printf("%x", payload[x]);
        }

        uint8_t* newdata;
        uint32_t* dsize = (uint32_t*)malloc(sizeof(uint32_t));

        if (protocol == 253){
            printf("\nADDING TO RR_record\n");
            newdata = add_RR_route(test, 5, dsize);
            print_RR_shim(newdata);    
        }
        else{
            printf("\nADDING SHIM LAYER\n");
            newdata = add_RR_shim(test, 5, dsize);
            print_RR_shim(newdata);
        }


        printf("\n\n DATA: \n\n");
        printf("DSIZE: %d \n\n", *dsize);

        int y;
        for (y = 0; y < *dsize; y++)
        {
            printf("%02x", newdata[y]);
        }

        printf("\nFINISHED\n");


        int ver = nfq_set_verdict(qh, id, NF_ACCEPT, *dsize, newdata);
        free(newdata);
        free(dsize);
        return ver;
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