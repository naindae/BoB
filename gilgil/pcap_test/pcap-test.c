#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>

#define ETHER_ADDR_LEN 6

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
	printf("MAC  %02x:%02x:%02x:%02x:%02x:%02x  ->  ",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n\n",mac[6],mac[7],mac[8],mac[9],mac[10],mac[11]);
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
	printf("syntax: pcap-test <interface>\n");
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

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n\n", header->caplen);
		struct libnet_ethernet_hdr *ethernet_hdr = (struct libnet_ethernet_hdr *)packet;
		int packet_len=14;
		print_mac(ethernet_hdr->ether_dhost);
		if(ethernet_hdr->ether_type == 8){		//ip protocol check
		
			struct libnet_ipv4_hdr *ipv4_hdr = (struct libnet_ipv4_hdr *)(packet+sizeof(struct libnet_ethernet_hdr));
			print_ip((u_int8_t *)&ipv4_hdr->ip_src);
			packet_len+=ipv4_hdr->ip_hl*4; // ethernet header len + ip header len
			
			if(ipv4_hdr->ip_p == 6){		//tcp protocol check
			
				struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *)(packet+sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_ipv4_hdr));
				print_port((u_int8_t *)&tcp_hdr->th_sport);
				
				int tcp_len=(tcp_hdr->th_off>>4)*4; 	// tcp header len 1000 0000 -> 1000 * 4 -> 32
				packet_len+=tcp_len;			// packet_len
				
				if(header->caplen > packet_len){         // payload check
					printf("PAYLOAD %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x  			     \n\n",packet[packet_len],packet[packet_len+1],packet[packet_len+2],packet[packet_len+3],packet[packet_len+4],packet[packet_len+5],packet[packet_len+6],packet[packet_len+7],packet[packet_len+8],packet[packet_len+9]);
				}
				
				printf("------------------------------------------------------------------\n");				
			}
		}
		
	}

	pcap_close(pcap);
}
