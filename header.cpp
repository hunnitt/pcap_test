#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "header.h"

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
    p += sizeof(TCP_HDR);
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
    return ((n >> 8) | (n << 8))
}

