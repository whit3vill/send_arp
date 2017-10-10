#include "send_arp.h"

void GetMAC(u_int8_t *mac_addr, u_int8_t *interface) {
    int s;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name));
    s = socket(PF_INET, SOCK_DGRAM, 0);
    ioctl(s, SIOCGIFHWADDR, &ifr);
    close(s);
    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
}
 
// Ref: https://stackoverflow.com/questions/2283494/get-ip-address-of-an-interface-on-linux
void GetIP(u_int8_t *ip_addr, u_int8_t *interface) {
    int s;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    s = socket(AF_INET, SOCK_DGRAM, 0);
    ioctl(s, SIOCGIFADDR, &ifr);
    close(s);
    memcpy(ip_addr, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, IP_ADDR_LEN);
}

void MakeARP(u_int8_t *packet, u_int8_t *src_mac, u_int8_t *dst_mac, u_int8_t *src_ip, u_int8_t *dst_ip, u_int16_t opcode) {
	struct arp_packet *apkt;

	apkt = (struct arp_packet *)malloc(sizeof(struct arp_packet));

	memcpy(apkt->ether_dhost, dst_mac, ETHER_ADDR_LEN);
	memcpy(apkt->ether_shost, src_mac, ETHER_ADDR_LEN);
	apkt->ether_type = htons(ETHERTYPE_ARP);

	apkt->hw_type = htons(ARPHRD_ETHER);
	apkt->ip_type = htons(ETHERTYPE_IP);
	apkt->hw_len  = ETHER_ADDR_LEN;
	apkt->ip_len  = IP_ADDR_LEN;
	apkt->opcode  = htons(opcode);

	memcpy(apkt->src_hw_addr, src_mac, ETHER_ADDR_LEN);
	memcpy(apkt->src_ip_addr, src_ip, IP_ADDR_LEN);
	memcpy(apkt->dst_hw_addr, dst_mac, ETHER_ADDR_LEN);
	memcpy(apkt->dst_ip_addr, dst_ip, IP_ADDR_LEN);

	memcpy(packet, epkt, sizeof(struct arp_packet));
	free(apkt);
}