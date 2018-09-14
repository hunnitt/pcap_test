#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ethernet_header {
    char dest_addr[6];
    char src_addr[6];
    char type[2];
}ETH_HDR;

struct IP_header {
    char 
}IP_HDR;

struct TCP_header {
    const u_char 
}TCP_HDR;

struct payload {
    const u_char data [32];
}DATA;


void usage(void) {
    printf("syntax : pcap_test <interface>\n");
    printf("sample : pcap_test ens33\n");
}

int parse(ETH_HDR * eth_hdr, 
           IP_HDR * ip_hdr, 
           TCP_HDR * tcp_hdr, 
           DATA * data, 
           const u_char * packet) {

   char * p = packet;
   
   memcpy(eth_hdr, p, sizeof(eth_hdr));
   p += sizeof(eth_hdr);

   if(memcmp(eth_hdr->type, 0x0800)) {
       printf("it isn't IP Datagram.\n");
       return -3;
   }

   memcpy(ip_hdr, p, sizeof(ip_hdr);
   p += sizeof(ip_hdr);


   if(memcmp(ip_hdr->PROTOCOL_ID,
}

int main(int argc, char * argv[]) {
    if(argc != 2) {
        usage();
        return -1;
    }

    char * dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * handle = pcap_open_live(dec, BUFSIZ, 1, 1000, errbuf);

    if(handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1
    }

    while(1) {
        struct pcap_pkthdr * header;
        const u_char * packet;
        int result = pcap_next_ex(handle, &header, &packet);
        ETH_HDR * ethhdr = malloc(sizeof(ETH_HDR));
        IP_HDR * iphdr = malloc(sizeof(IP_HDR));
        TCP_HDR * tcphdr = malloc(sizeof(TCP_HDR));
        DATA * payload = malloc(sizeof(DATA));


        // 0 : packets are being read from a live capture, 
        //     and the timeout expired
        if(result == 0) continue;
        // -1 : an error occurred while reading the packet
        // -2 : there are no more packets to read from the savefile
        if(result == -1 || result == -2) break;
        printf("%u bytes captured\n", header->caplen);
        parse(ethhdr, iphdr, tcphdr, payload, packet);

        freeall(
    }

    pcap_close(handle);
    return 0;
}
