#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "header.h"

void usage(void) {
    printf("syntax : pcap_test <interface>\n");
    printf("sample : pcap_test ens33\n");
}

int main(int argc, char * argv[]) {
    if(argc != 2) {
        usage();
        return -1;
    }

    char * dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

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

        printf("%u bytes captured\n", header->caplen);
        printf("\n");

        // Ethernet info Print
        printf("ETH header info\n");
        printf("> Source MAC : ");
        for(int i=0; i<6; i++) {
            printf("%02X", ethhdr->SRC_MAC[i]);
            if(i!=5) printf(":");
            else printf("\n");
        }
        printf("> Destination MAC : ");
        for(int i=0; i<6; i++) {
            printf("%02X", ethhdr->DEST_MAC[i]);
            if(i!=5) printf(":");
            else printf("\n");
        }
        printf("\n");

        // IP info Print
        printf("IP header info\n");
        printf("> Source IP : ");
        for(int i=0; i<4; i++) {
            printf("%d", iphdr->SRC_IP[i]);
            if(i!=3) printf(".");
            else printf("\n");
        }
        printf("> Destination IP : ");
        for(int i=0; i<4; i++) {
            printf("%d", iphdr->DEST_IP[i]);
            if(i!=3) printf(".");
            else printf("\n");
        }
        printf("\n");

        // TCP info Print
        printf("TCP header info\n");
        tcphdr->SRC_PORT = byteswap(tcphdr->SRC_PORT);
        tcphdr->DEST_PORT = byteswqp(tcphdr->DEST_PORT);

        printf("> Source port number : %d\n", tcphdr->SRC_PORT);
        printf("> Destination port number : %d\n", tcphdr->DEST_PORT);
        printf("\n");

        // payload Print
        printf("Payload\n");
        u_char * p = payload->data;
        for(int i=0; i<32; i++) {
            printf("%02X ", *p);
            p++;
            if((i & 0x0F) == 0x0F)
                printf("\n");
        }
        printf("\n");
        freeall(ethhdr, iphdr, tcphdr, payload); 
    }

    pcap_close(handle);
    return 0;
}

