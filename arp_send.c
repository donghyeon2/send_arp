#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <string.h>

#define p_size 1024

char packet[p_size];

void send_arp();

struct ip_H{
	unsigned char ip_v4:4, ip_hl:4;
	unsigned char ip_tos;
	unsigned short int ip_len;
	unsigned short int ip_id;
	unsigned short int ip_off;
	unsigned char ip_ttl;
	unsigned char ip_p;
	unsigned short int ip_sum;
	unsigned int ip_src;
	unsigned int ip_dst;
}__attribute__((packed));

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
	send_arp();
	return 0;
}

void send_arp(){
	struct ether_header *ep;
	ep = (struct ether_header*)packet;
	for(int i=0; i<6; i++){
		ep->ether_dhost[i] = 0xff;
	}
	ep->ether_shost[0] = 0x00;
	ep->ether_shost[1] = 0x0c;
	ep->ether_shost[2] = 0x29;
	ep->ether_shost[3] = 0x53;
	ep->ether_shost[4] = 0xd5;
	ep->ether_shost[5] = 0x90;
	ep->ether_type = ntohs(ETHERTYPE_ARP);
	memcpy(packet, ep->ether_dhost, 6);
	memcpy(packet+6, ep->ether_shost, 6);
}
