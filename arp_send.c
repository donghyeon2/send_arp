#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <string.h>
#include <net/if_arp.h>

#define p_size 128
#define PROTO_TYPE 0x04
#define HARD_TYPE 0x06

char packet[p_size];

struct mac_ip{
	u_char s_mac[6];
	u_char s_ip[4];
	u_char d_mac[6];
	u_char d_ip[4];
}__attribute((__packed__));
char* send_arp(char *s_ip, char *d_ip);

int main(int argc, char* argv[]){
	pcap_t *fd;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	memset(packet, 0, sizeof(packet));
	fd = pcap_open_live(argv[1], 65536, 0, 1000, errbuf); //maxlength of packet 65536//
	if (fd == NULL){
		printf("device error %s \n", errbuf);
		exit(1);
	}
	printf("BEST OF THE BEST 6TH ARP PACKET SENDER \t \n");
	printf("BY github.com/donghyeon2 \t \n");
	if(argc =! 3){
		printf("***FOLLOW THIS [DEV] [MY_IP] [TARGET_IP]***\n");
		exit(1);
	}
	send_arp(argv[2], argv[3]);
	pcap_sendpacket(fd, packet, 42);
	return 0;
}

char *send_arp(char *s_ip, char*d_ip){
	struct ether_header *ep;
	ep = (struct ether_header*)packet;
	struct arphdr *arph;
	arph = (struct arphdr*)packet+sizeof(ep);
	struct mac_ip *adr;
	adr = (struct mac_ip*)packet+sizeof(ep)+sizeof(arph);
	for (int i = 0; i <6; i++)
	{
		ep->ether_dhost[i] = 0xff;
	}
	ep->ether_shost[0] = 0x78;
	ep->ether_shost[1] = 0x4f;
	ep->ether_shost[2] = 0x43;
	ep->ether_shost[3] = 0x78;
	ep->ether_shost[4] = 0xb9;
	ep->ether_shost[5] = 0x1f;
	ep->ether_type = ntohs(ETHERTYPE_ARP);
	memcpy(packet, ep, sizeof(ep));
	arph->ar_hrd = htons(ARPHRD_ETHER);
	arph->ar_pro = htons(ETHERTYPE_IP);
	arph->ar_hln = HARD_TYPE;
	arph->ar_pln = PROTO_TYPE;
	arph->ar_op = htons(ARPOP_REQUEST);
	memcpy(packet+14, arph, 8);
	inet_pton(AF_INET, s_ip, adr->s_ip); // converting to bit
	memcpy(adr->s_mac, ep->ether_shost, 6);
	inet_pton(AF_INET, d_ip, adr->d_ip); // also @_@..
	memcpy(adr->d_mac, ep->ether_dhost, 6);
	memcpy(packet+22, adr, 20);
}
//78:4f:43:78:b9:1f //