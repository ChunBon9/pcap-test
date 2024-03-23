#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>

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

typedef struct{
	uint8_t des_MAC[6];
	uint8_t src_MAC[6];
	uint8_t eth_Type[2];	
}eth_header;

typedef struct{
	uint8_t v_N_len;
	uint8_t tos;
	uint8_t t_Length[2];
	uint8_t id[2];
	uint8_t frag_Off[2];
	uint8_t ttl;
	uint8_t protocol;
	uint8_t hd_Chksum[2];
	uint8_t src_Addr[4];
	uint8_t des_Addr[4];
}ip_header;

typedef struct{
	uint8_t src_Port[2];
	uint8_t des_Port[2];
	uint8_t seq_Num[4];
	uint8_t ack_Num[4];
	uint8_t off_N_rsrv;
	uint8_t flags;
	uint8_t win_Size[2];
	uint8_t chksum[2];
	uint8_t urg_P[2];
}tcp_header;

typedef struct{
	eth_header eth_hd;
	ip_header  ip_hd;
	tcp_header tcp_hd;
	uint8_t    data[20];
}Packet;

void read_MAC(uint8_t* mac) {
	int i=0;
	for(i=0; i<5; i++)
	{
		printf("%02x::", mac[i]);
	}
	printf("%02x\n", mac[i]);
}

void read_IP(uint32_t* addr) {
	int i;
	uint32_t ip = ntohl(*addr); 
	for(i=3; i>0; i--)
	{
		printf("%u.", (ip >> (i * 8)) & 0x000000FF);
	}
	printf("%u\n", (ip >> (i * 8)) & 0x000000FF);
}

void read_PORT(uint16_t* addr) {
	int i;
	uint16_t port = ntohs(*addr);
	printf("%u\n", port);
}

void print_DATA(uint8_t* data) {
	printf("DATA             = ");
	for(int i=0; i<20; i++) {
		printf("%02X ", data[i]);
		if(i % 16 == 15) printf("\n                   ");
	}
	printf("\n\n");
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
		printf("%u bytes captured\n", header->caplen);
		Packet *pkt = (Packet*)packet;
		
		if(pkt->ip_hd.protocol == 6) {
			printf("SOURCE       MAC = ");
			read_MAC(pkt->eth_hd.src_MAC);
			printf("DESTINATION  MAC = ");
			read_MAC(pkt->eth_hd.des_MAC);
			
			printf("SOURCE        IP = ");
			read_IP((uint32_t*)(pkt->ip_hd.src_Addr));
			printf("DESTINATION   IP = ");
			read_IP((uint32_t*)(pkt->ip_hd.des_Addr));
			
			printf("SOURCE      PORT = ");
			read_PORT((uint16_t*)(pkt->tcp_hd.src_Port));
			printf("DESTINATION PORT = ");
			read_PORT((uint16_t*)(pkt->tcp_hd.des_Port));
			
			print_DATA(pkt->data);
		}
	}
	pcap_close(pcap);
}
