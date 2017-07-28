#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#define p_size 1024

const unsigned char* packet[p_size];
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
	printf("\t Best of the Best 6th ARP_SENDER \t\n");
	printf("Usage : [adapter] [ip] [gateway] \n");
	return 0;
}

void send_arp(){
	struct ether_header *ep;
	struct ip_H *ip;
	ep->ether_dhost[0] = "\xff";
	ep->ether_dhost[1] = "\xff";
	ep->ether_dhost[2] = "\xff";
	ep->ether_dhost[3] = "\xff";
	ep->ether_dhost[4] = "\xff";
	ep->dhost[5] = "\xff";
	ep->shost[0] = "\x12";
	ep->shost[1] = "\x34";
	ep->shost[2] = "\x56";
	ep->shost[3] = "\x78";
	ep->shost[4] = "\x9a";
	ep->shost[5] = "\xbc";

	ep->etheR_type = htons(ETHERTYPE_ARP);
	
	memcpy(ip->ip_src, 1, sizeof(ip->ip_src));
	for(int i=0; i<6; i++){
		packet[i] = ep->dhost[i];
		for(int j=6; j<12; j++){
			packet[i] = ep->shost[i];
		}
	}

}
