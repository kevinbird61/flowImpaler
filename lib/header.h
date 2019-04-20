#ifndef __PACKET_HEADER__
#define __PACKET_HEADER__

#include <pcap/pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ether.h>

/* Reference from: https://www.tcpdump.org/pcap.html */
/* Ethernet address are 6 bytes */
// #define ETHER_ADDR_LEN 6

/* Ethernet header */
struct sniff_ethernet {
    u_char dstAddr[ETHER_ADDR_LEN]; // dest addr
    u_char srcAddr[ETHER_ADDR_LEN]; // src addr
    u_short etherType; 
};

/* IPv4 header */
struct sniff_ipv4 {
    u_char vhl;     // version << 4 | header length >> 2
    u_char tos;     // type of service 
    u_short len;    // total length
    u_short id;     // identification
    u_short off;    // fragment offset field 
#define IP_RF 0x8000 // reserved fragment flag
#define IP_DF 0x4000 // dont fragment flag
#define IP_MF 0x2000 // more fragment flag
#define IP_OFFMASK 0x1fff // mask for fragmenting bits
    u_char ttl;     // time to live
    u_char protocol; // protocol
    u_short checksum;   // checksum
    struct in_addr srcAddr, dstAddr; // source and destination IP addr
};
#define IP_HL(ip)		(((ip)->vhl) & 0x0f)
#define IP_V(ip)		(((ip)->vhl) >> 4)

/* TODO: IPv6 header */

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short sport;  // source port
    u_short dport;  // destination port
    tcp_seq seq;    // sequence number
    tcp_seq ack;    // acknowledgement number
    u_char offx2;   // data offset, rsvd;
#define TH_OFF(th)      (((th)->offx2 & 0xf0) >> 4)
    u_char flags;   
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short win;		/* window */
    u_short checksum;		/* checksum */
    u_short urp;		/* urgent pointer */
};

/* UDP header */
struct sniff_udp {
    u_short sport;
    u_short dport;
    u_short length;
    u_short checksum;
};

/* ICMP */
struct sniff_icmp {
    u_char type;
    u_char code;
    u_short checksum;
    u_short id;
    u_short seq;
};

#endif 