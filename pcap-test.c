#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	uint8_t dmac[6];
	uint8_t smac[6];
	uint16_t type;
} Ethernet;

typedef struct {
	uint8_t ihl;
	uint8_t tos;
	uint16_t total_len;
	uint16_t identification;
	uint16_t fragment;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint8_t sip[4];
	uint8_t dip[4];
} IP;

typedef struct {
	uint16_t sport;
	uint16_t dport;
	uint32_t sequence;
	uint32_t acknowlegment;
	uint8_t data_offset;
	uint8_t flags;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgent_pointer;
} TCP;


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

void print_mac(const uint8_t* mac) {
	printf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[3], mac[4], mac[5]);
}

void print_ip(const uint8_t* ip) {
	printf("%d.%d.%d.%d", (int)ip[0], (int)ip[1], (int)ip[2], (int)ip[3]);
}

void print_payload(const uint8_t* payload, size_t payload_len) {
	if (payload_len > 20) payload_len = 20;

	for (size_t i = 0; i < payload_len; i++) {
		printf("%02X", payload[i]);
		if (i < payload_len - 1) printf(" ");
	}

	printf("\n");
}

void print_packet(const struct pcap_pkthdr* header, const u_char* packet) {
	if (header->caplen < sizeof(Ethernet))
		return;

	const Ethernet* ethernet = (const Ethernet*)packet;

	if (ntohs(ethernet->type) != 0x0800)
		return;

	if (header->caplen < sizeof(Ethernet) + sizeof(IP))
		return;

	const IP* ip = (const IP*)(packet + sizeof(Ethernet));

	uint8_t ip_version = ip->ihl >> 4;
	size_t ip_header_len = (size_t)(ip->ihl & 0x0F) * 4;

	if (ip_version != 4)
		return;

	if (ip_header_len < sizeof(IP))
		return;

	if (header->caplen < sizeof(Ethernet) + ip_header_len)
		return;

	if (ip->protocol != 6)
		return;

	uint16_t fragment = ntohs(ip->fragment);
	uint16_t fragment_offset = fragment &0x1FFF;

	if (fragment_offset != 0)
		return;

	size_t tcp_offset = sizeof(Ethernet) + ip_header_len;

	if (header->caplen < tcp_offset + sizeof(TCP))
		return;

	const TCP* tcp = (const TCP*)(packet + tcp_offset);

	size_t tcp_header_len = (size_t)(tcp->data_offset >>4) * 4;

	if (tcp_header_len < sizeof(TCP))
		return;

	uint16_t ip_total_len = ntohs(ip->total_len);

	if (ip_total_len < ip_header_len + tcp_header_len)
		return;

	size_t payload_offset = tcp_offset + tcp_header_len;

	size_t payload_len = ip_total_len - ip_header_len - tcp_header_len;

	printf("===================================\n");
	printf("src mac: ");
	print_mac(ethernet->smac);
	printf("  dst mac: ");
	print_mac(ethernet->dmac);
	printf("\n");

	printf("src ip: ");
	print_ip(ip->sip);
	printf("  dst ip: ");
	print_ip(ip->dip);
	printf("\n");

	printf("src port: %u", (unsigned int)ntohs(tcp->sport));
	printf("  dst port: %u\n", (unsigned int)ntohs(tcp->dport));	

	print_payload(packet + payload_offset, payload_len);
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
		print_packet(header, packet);
	}

	pcap_close(pcap);
}
