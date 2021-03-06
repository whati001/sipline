//
// Created by akarner on 4/4/21.
//

#ifndef SIPLINE_SIPNET_H
#define SIPLINE_SIPNET_H

#include <netinet/in.h>

/**
 * Ethernet header information
 */
#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14
#define ETHER_IP 0x800
struct sipline_ethernet_header {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/**
 * IP header information
 */
#define IP_PROTO_UDP 17
#define IP_MIN_LENGHT 8
#define IP_HL(ip)        (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)
#define IP_RF 0x8000        /* reserved fragment flag */
#define IP_DF 0x4000        /* don't fragment flag */
#define IP_MF 0x2000        /* more fragments flag */
#define IP_OFFMASK 0x1fff    /* mask for fragmenting bits */
struct sipline_ip_header {
    u_char ip_vhl;        /* version << 4 | header length >> 2 */
    u_char ip_tos;        /* type of service */
    u_short ip_len;        /* total length */
    u_short ip_id;        /* identification */
    u_short ip_off;        /* fragment offset field */
    u_char ip_ttl;        /* time to live */
    u_char ip_p;        /* protocol */
    u_short ip_sum;        /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};


/**
 * IP UDP header struct
 */
#define SIZE_UDP 8
struct sipline_udp_header {
    u_short uh_sport;
    u_short uh_dport;
    u_short uh_len;
    u_short uh_sum;
};

#endif //SIPLINE_SIPNET_H
