#include "send_arp.h"

void GetMAC(uint8_t *mac_addr, uint8_t *interface) {
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
void GetIP(uint8_t *ip_addr, uint8_t *interface) {
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

void printMAC(uint8_t *mac_addr) {
   int i;

   for(i=0;i<6;i++) {
      printf("%02x:", mac_addr[i]);
      if(i == 4)   printf("%02x\n", mac_addr[i++]);
   }
}
void printIP(uint8_t *ip_addr) {
   int i;

   for(i=0;i<4;i++) {
      printf("%d.", ip_addr[i]);
      if(i == 2)   printf("%d\n", ip_addr[i++]);
   }
}

void SendARP(uint8_t *src_mac, uint8_t *src_ip, uint8_t *dst_mac, uint8_t *dst_ip, u_int16_t opcode, pcap_t *handle) {
   struct arp_packet *apkt;
   unsigned char *packet;

   apkt   = (struct arp_packet *)malloc(sizeof(struct arp_packet));
   packet = (unsigned char *)malloc(sizeof(struct arp_packet));

   if(dst_mac == NULL) memcpy(apkt->ether_dhost, "\xff\xff\xff\xff\xff\xff", ETHER_ADDR_LEN);
   else memcpy(apkt->ether_dhost, dst_mac, ETHER_ADDR_LEN);
   memcpy(apkt->ether_shost, src_mac, ETHER_ADDR_LEN);
   apkt->ether_type = htons(ETHERTYPE_ARP);

   apkt->hw_type = htons(ARPHRD_ETHER);
   apkt->ip_type = htons(ETHERTYPE_IP);
   apkt->hw_len  = ETHER_ADDR_LEN;
   apkt->ip_len  = IP_ADDR_LEN;
   apkt->opcode  = htons(opcode);

   memcpy(apkt->src_hw_addr, src_mac, ETHER_ADDR_LEN);
   memcpy(apkt->src_ip_addr, src_ip, IP_ADDR_LEN);
   if(dst_mac == NULL) memcpy(apkt->dst_hw_addr, "\x00\x00\x00\x00\x00\x00", ETHER_ADDR_LEN);
   else memcpy(apkt->dst_hw_addr, dst_mac, ETHER_ADDR_LEN);
   memcpy(apkt->dst_ip_addr, dst_ip, IP_ADDR_LEN);

   memcpy(packet, apkt, sizeof(struct arp_packet));
   free(apkt);

   pcap_sendpacket(handle, packet, sizeof(packet));
   free(packet);
}

void GetMAC2(pcap_t *handle, uint8_t *tmp) {
   struct arp_packet *apkt;
   struct pcap_pkthdr *header;
   const u_char *packet;

   while(1) {
      pcap_next_ex(handle, &header, &packet);

      apkt = (struct arp_packet *)packet;
      if(ntohs(apkt->ether_type) == ETHERTYPE_ARP && ntohs(apkt->opcode) == ARPOP_REPLY) break;
   }
   
   memcpy(tmp,apkt->src_hw_addr,ETHER_ADDR_LEN);
}
