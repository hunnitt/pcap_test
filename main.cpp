#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "header.h"


int main(int argc, char * argv[]) {
    if(argc != 2) {
        usage();
        return -1;
    }

    char * dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    // for debugging.
    // pcap_t * handle = pcap_open_offline("/home/donghunkim/Desktop/pcap_test/testfile/tcp-port-80-test.gilgil.pcap", errbuf);
    

    if(handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    while(1) {
        struct pcap_pkthdr * header;
        const u_char * packet;
        int result = pcap_next_ex(handle, &header, &packet);

        ETH_HDR * ethhdr = (ETH_HDR *)malloc(sizeof(ETH_HDR));
        IP_HDR * iphdr = (IP_HDR *)malloc(sizeof(IP_HDR));
        TCP_HDR * tcphdr = (TCP_HDR *)malloc(sizeof(TCP_HDR));
        DATA * payload = (DATA *)malloc(sizeof(DATA));

        // 0 : packets are being read from a live capture, 
        //     and the timeout expired
        if(result == 0) continue;
        // -1 : an error occurred while reading the packet
        // -2 : there are no more packets to read from the savefile
        if(result == -1 || result == -2) break;

        parse(ethhdr, iphdr, tcphdr, payload, packet);
        
        if(ethhdr->TYPE != 0x08 || iphdr->PROTOCOL_ID != 0x06) {
            freeall(ethhdr, iphdr, tcphdr, payload);
            continue;
        }

        printf("\n===============================================\n\n");
        printf("%u bytes captured\n", header->caplen);
        printf("\n");

        // Ethernet info Print
        printf("ETH header info\n");
        printf("> Source MAC : ");
        dump_MAC(ethhdr, 's');
        printf("> Destination MAC : ");
        dump_MAC(ethhdr, 'd');
        printf("\n");

        // IP info Print
        printf("IP header info\n");
        printf("> Source IP : ");
        dump_IP(iphdr, 's');
        printf("> Destination IP : ");
        dump_IP(iphdr, 'd');
        printf("\n");

        // TCP info Print
        printf("TCP header info\n");
        tcphdr->SRC_PORT = byteswap(tcphdr->SRC_PORT);
        tcphdr->DEST_PORT = byteswap(tcphdr->DEST_PORT);

        printf("> Source port number : %d\n", tcphdr->SRC_PORT);
        printf("> Destination port number : %d\n", tcphdr->DEST_PORT);
        printf("\n");

        // payload Print
        printf("Payload\n");
        int datalen = byteswap(iphdr->TOTAL_LENGTH) 
                      - (iphdr->HEADER_LENGTH)*4
                      - (tcphdr -> OFFSET)*4;
        int printlen = 32 < datalen ? 32 : datalen;

        u_char * p = payload->data;
        for(int i=0; i<printlen; i++) {
            printf("%02X ", *p);
            p++;
            if((i & 0x0F) == 0x0F)
                printf("\n");
        }
        printf("\n");
        freeall(ethhdr, iphdr, tcphdr, payload); 
    }
    printf("\n===============================================\n\n");

    pcap_close(handle);
    return 0;
}

