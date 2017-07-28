#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <string.h>

#define p_size 128

char packet[p_size];

char* send_arp(char *s_ip, char *d_ip);

struct arp_header{
	u_short hard_type; //2 byte//
	u_short procol_type; //2 byte//
	u_char hard_size; //1 byte//
	u_char procol_size; //1 byte//
	u_short operation; //2 byte//
	u_char s_mac[6]; //6 byte//
	u_char s_ip[INET_ADDRSTRLEN]; //16 byte//
	u_char d_mac[6];//6 byte//
	u_char d_ip[INET_ADDRSTRLEN];//16 byte//
}__attribute__((packed));

int main(int argc, char* argv[]){
	pcap_t *fd;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	memset(packet, 0, sizeof(packet));
	if(argc =! 3){
		printf("use this [dev] [my-ip] [target -ip]");
		exit(1);
	}
	fd = pcap_open_live(argv[1], 65536, 0, 1000, errbuf); //maxlength of packet 65536//
	if (fd == NULL){
		printf("device error %s \n", errbuf);
		exit(1);
	}
	printf("\t BEST OF THE BEST 6TH ARP PACKET SENDER \t \n");
	printf("\t BY donghyeon2 \t \n");
	send_arp(argv[2], argv[3]);
	pcap_sendpacket(fd, packet, sizeof(packet));
	return 0;
}

char *send_arp(char *s_ip, char*d_ip){
	struct ether_header *ep;
	struct arp_header *arp;
	ep = (struct ether_header*)packet;
	arp = (struct arp_header*)packet+14;
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
	memcpy(packet, ep, sizeof(ep));
	arp->hard_type = 0x01;
	arp->procol_type = ETHERTYPE_IP;
	arp->hard_size = 0x06;
	arp->procol_size = 0x04;
	arp->operation = 0x01;
	memcpy(arp->s_mac, ep->ether_shost, 6);
	inet_pton(AF_INET, s_ip, arp->s_ip);
	memcpy(arp->d_mac, ep->ether_dhost, 6);
	inet_pton(AF_INET, d_ip, arp->d_ip);
	memcpy(packet+14, arp, sizeof(arp));
	memset(packet+66, 0, sizeof(packet));
	return packet;
}
