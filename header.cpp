#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "header.h"

void usage(void) {
    printf("syntax : pcap_test <interface>\n");
    printf("sample : pcap_test ens33\n");
}

void dump_MAC(ETH_HDR * eth_hdr, char id) {
    if (id == 's') {
        for(int i=0; i<6; i++) {
                printf("%02X", eth_hdr->SRC_MAC[i]);
                if(i!=5) printf(":");
                else printf("\n");
        }
    }
    else if (id == 'd'){
        for(int i=0; i<6; i++) {
                printf("%02X", eth_hdr->DEST_MAC[i]);
                if(i!=5) printf(":");
                else printf("\n");
        }
    }
    else
        printf("please enter the s or d\n");
}

void dump_IP(IP_HDR * ip_hdr, char id){
    if (id == 's') {
        for(int i=0; i<4; i++) {
            printf("%d", ip_hdr->SRC_IP[i]);
            if(i!=3) printf(".");
            else printf("\n");
        }
    }
    else if (id == 'd'){
        for(int i=0; i<4; i++) {
            printf("%d", ip_hdr->DEST_IP[i]);
            if(i!=3) printf(".");
            else printf("\n");
        }
    }
    else
        printf("please enter the s or d\n");
}

void parse(ETH_HDR * eth_hdr, 
          IP_HDR * ip_hdr, 
          TCP_HDR * tcp_hdr, 
          DATA * data, 
          const u_char * packet) {
    const u_char * p = packet;
    memcpy(eth_hdr, p, sizeof(ETH_HDR));
    p += sizeof(ETH_HDR);
    memcpy(ip_hdr, p, sizeof(IP_HDR));
    p += (ip_hdr->HEADER_LENGTH)*4;
    memcpy(tcp_hdr, p, sizeof(TCP_HDR));
    p += (tcp_hdr->OFFSET)*4;
    memcpy(data, p, sizeof(DATA));
}

void freeall(ETH_HDR * eth_hdr,
             IP_HDR * ip_hdr,
             TCP_HDR * tcp_hdr,
             DATA * data) {
    free(eth_hdr);
    free(ip_hdr);
    free(tcp_hdr);
    free(data);
}

u_int16_t byteswap(u_int16_t n) {
    return ((n >> 8) | (n << 8));
}

