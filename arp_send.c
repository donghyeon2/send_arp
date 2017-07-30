#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <string.h>
#include <net/if_arp.h>
#include <net/if.h> // using ifreq with get macaddr
#include <sys/ioctl.h> // using ioctl function
#include <time.h>

#define p_size 42
#define PROTO_TYPE 0x04
#define HARD_TYPE 0x06

char s_packet[p_size];
char d_packet[p_size];

struct mac_ip{
	u_char s_mac[6];
	u_char s_ip[4];
	u_char d_mac[6];
	u_char d_ip[4];
}__attribute__((__packed__));

/*struct p_arphdr{
	u_int16_t hardt;
	u_int16_t prott;
	u_char hlen;
	u_char plen;
	u_int16_t oper;
	u_char s_mac[6];
	u_char s_ip[4];
	u_char t_mac[6];
	u_char t_ip[4];
}__attribute__((__packed__));*/

void send_arp(char* mac, char *s_ip, char *d_ip);
char *get_macaddr(char *ether);
void parsing_packet(d_packet);

int main(int argc, char* argv[]){
	pcap_t *fd, *fs;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	bpf_u_int32 net=0, mask=0;
	struct pcap_pkthdr header;
	int res=0;
	const u_char *p = d_packet;
	memset(s_packet, 0, sizeof(p_size));
	memset(d_packet, 0, sizeof(p_size));
	
	if(argc =! 3){
		printf("***FOLLOW THIS [DEV] [MY_IP] [TARGET_IP]***\n");
		exit(1);
	}
	fd = pcap_open_live(argv[1], 65536, 0, 1000, errbuf); //maxlength of packet 65536//
	fs = pcap_open_live(argv[1], 65536, 0, 1000, errbuf);
	if (fd == NULL || fs == NULL){
		printf("device error %s \n", errbuf);
		exit(1);
	}
	if(pcap_lookupnet(argv[1], &net, &mask, errbuf) == -1){
		printf("%s \n", errbuf);
		exit(1);
	}
	if(pcap_compile(fs, &fp, "arp", 1, mask) == -1){
		printf("%s \n", errbuf);
	}
	if(pcap_setfilter(fs, &fp) == -1){
			printf("%s \n", errbuf);
			exit(1);
	}
	printf("\t BEST OF THE BEST 6TH ARP PACKET SENDER \t \n");
	printf("\t BY github.com/donghyeon2 \t \n");
	send_arp(argv[1], argv[2], argv[3]);
	pcap_sendpacket(fd, s_packet, 42);
	while(res = pcap_next_ex(fs, &header, &p)>=0){
		if(res==0){
			printf(" NO ! \n"); //debug//
			continue;
		}
		sleep(3);
		if(p[21] == 2){
			printf("\t ------------------------------------------ \n");
			printf("\t target MAC : %02X:%02X:%02X:%02X:%02X:%02X \n",
				p[0], p[1], p[2],
				p[3], p[4], p[5]);
			printf("\t sender MAC : %02X:%02X:%02X:%02X:%02X:%02X \n",
				p[6], p[7], p[8], 
				p[9], p[10], p[11]);
		
		}
	return 0;
	}
}
char *get_macaddr(char *ether){
	int fd;
	struct ifreq ifr;
	char *iface = ether;
	unsigned char *mac;
	fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	close(fd);
	mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
	return mac;
}

void send_arp(char* mac, char *s_ip, char*d_ip){
	struct ether_header *ep;
	ep = (struct ether_header*)s_packet;
	struct arphdr *arph;
	arph = (struct arphdr*)s_packet+sizeof(ep);
	struct mac_ip *adr;
	adr = (struct mac_ip*)s_packet+sizeof(ep)+sizeof(arph);
	u_char parsing_mac[6];

	for (int i = 0; i <6; i++)
	{
		ep->ether_dhost[i] = 0xff; //broadcast//
	}
	memcpy(parsing_mac, get_macaddr(mac), 6);
	memcpy(ep->ether_shost, parsing_mac, 6);
	ep->ether_type = ntohs(ETHERTYPE_ARP);
	memcpy(s_packet, ep, sizeof(ep));
	arph->ar_hrd = htons(ARPHRD_ETHER);
	arph->ar_pro = htons(ETHERTYPE_IP);
	arph->ar_hln = HARD_TYPE;
	arph->ar_pln = PROTO_TYPE;
	arph->ar_op = htons(ARPOP_REQUEST);
	memcpy(s_packet+14, arph, 8);
	inet_pton(AF_INET, s_ip, adr->s_ip); // converting to bit
	memcpy(adr->s_mac, ep->ether_shost, 6);
	inet_pton(AF_INET, d_ip, adr->d_ip); // also @_@..
	memcpy(adr->d_mac, ep->ether_dhost, 6);
	memcpy(s_packet+22, adr, 20);
}
/*void parsing_packet(pcap_t *fd){
	int i=0;
	struct pcap_pkthdr header;
	struct p_arphdr *ap;
	ap = (struct p_arphdr*)d_packet+14;
	while(1){
		i = pcap_next_ex(fd, &header, &d_packet);
			printf("\t ------------------------------------------ \n");
			printf("\t sender MAC : %02X:%02X:%02X:%02X:%02X:%02X \n",
				ap->s_mac[0], ap->s_mac[1], ap->s_mac[2],
				ap->s_mac[3], ap->s_mac[4], ap->s_mac[5]);
			printf("\t target MAC : %02X:%02X:%02X:%02X:%02X:%02X \n",
				ap->t_mac[0], ap->t_mac[1], ap->t_mac[2], 
				ap->t_mac[3], ap->t_mac[4], ap->t_mac[5]);
		break;
	}
}
*/
