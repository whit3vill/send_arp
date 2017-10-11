#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <pcap.h>
//#include <libdnet/arp.h>
#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define IP_ADDR_LEN 4

struct arp_packet {
    u_char ether_dhost[6];
    u_char ether_shost[6];
    u_short ether_type;               

	u_int16_t hw_type;
    u_int16_t ip_type;
    u_int8_t hw_len;
    u_int8_t ip_len;
    u_int16_t opcode;
    u_int8_t src_hw_addr[6];
    u_int8_t src_ip_addr[4];
    u_int8_t dst_hw_addr[6];
    u_int8_t dst_ip_addr[4];
};
