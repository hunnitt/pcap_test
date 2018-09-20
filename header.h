#pragma once

typedef struct ethernet_header {
    u_int8_t DEST_MAC[6];
    u_int8_t SRC_MAC[6];
    u_int16_t TYPE;
}ETH_HDR;

typedef struct IP_header {
#if BYTE_ORDER == LITTLE_ENDIAN
    unsigned int HEADER_LENGTH:4;
    unsigned int VERSION:4;
#endif
#if BYTE_ORDER == BIG_ENDIAN
    unsigned int VERSION:4;
    unsigned int HEADER_LENGTH:4;
#endif
    u_int8_t TYPE_OF_SERVICE;
    u_int16_t TOTAL_LENGTH;
    u_int16_t IDENTIFIER;
    u_int16_t FRAGMENT_OFFSET;
    u_int8_t TIME_TO_LIVE;
    u_int8_t PROTOCOL_ID;
    u_int16_t HEADER_CHECKSUM;
    unsigned char SRC_IP[4];
    unsigned char DEST_IP[4];
}IP_HDR;

typedef struct TCP_header {
    u_int16_t SRC_PORT;
    u_int16_t DEST_PORT;
    u_int32_t SEQUENCE_NUM;
    u_int32_t ACKNOWLEDGE_NUM;
#if BYTE_ORDER == LITTLE_ENDIAN
    unsigned int RESERVED:4;
    unsigned int OFFSET:4;
#endif
#if BYTE_ORDER == BIG_ENDIAN
    unsigned int OFFSET:4;
    unsigned int RESERVED:4;
#endif
    u_int8_t FLAGS;
    u_int16_t WINDOW;
    u_int16_t CHECKSUM;
    u_int16_t URGENT_PTR;
}TCP_HDR;

typedef struct payload {
    unsigned char data[32];
}DATA;

void usage(void);

void dump_MAC(ETH_HDR * eth_hdr, char id);

void dump_IP(IP_HDR * ip_hdr, char id);

void parse(ETH_HDR * eth_hdr, IP_HDR * ip_hdr, TCP_HDR * tcp_hdr, DATA * data, const u_char * packet);

void freeall(ETH_HDR * eth_hdr, IP_HDR * ip_hdr,  TCP_HDR * tcp_hdr, DATA * data);

u_int16_t byteswap(u_int16_t n);

