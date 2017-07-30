all: arp_send
arp_send: arp_send.c
	gcc -o arp_send arp_send.c -lpcap
clean:
	rm arp_send
