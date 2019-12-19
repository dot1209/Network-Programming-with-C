#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

int i = 0;
int ip = 0;

char sip[100][INET_ADDRSTRLEN];
char dip[100][INET_ADDRSTRLEN];
int table[100] = {0};

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int main(int argc, char *argv[]) {

	pcap_t *descr;
	char errbuf[PCAP_ERRBUF_SIZE];

	// open capture file for offline processing
	descr = pcap_open_offline("tcp.pcapng", errbuf);

	if(descr == NULL) {

		printf("pcap_open_live() failed: %s\n", errbuf);
		return 1;
	}

	// start packet processing loop, just like live capture
	if(pcap_loop(descr, 0, packetHandler, NULL) < 0) {

		printf("pcap_loop() failed: %s\n", pcap_geterr(descr));
		return 1;
	}

	printf("total %d packet\n", ip);
	printf("capture %d finished\n", i);

	int a;
	for(a = 0; a < i; a++)	{
		if(table[a] > 0)
			printf("%s <---> %s : %d\n", sip[a], dip[a], table[a]);
	}

	return 0;
}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {

	const struct ether_header* ethernetHeader;
	const struct ip* ipHeader;
	const struct tcphdr* tcpHeader;
	char sourceIp[INET_ADDRSTRLEN];
	char destIp[INET_ADDRSTRLEN];
	const struct pcap_pkthdr *hdr = pkthdr;	

	u_int sourcePort, destPort;
	u_char *data;
	int dataLength = 0;

	int j;
	int flag = 0;

	ethernetHeader = (struct ether_header*)packet;

	if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {

		ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
		inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);

		if(i == 0)	{

			strcpy(sip[i], sourceIp);
			strcpy(dip[i], destIp);
			table[i]++;
			i++;
		}

		else	{

			for(j = 0; j < i; j++)	{

				if(strcmp(sourceIp, sip[j]) == 0 && strcmp(destIp, dip[j]) == 0)	{
					flag = 1;
					table[j]++;
				}

				else if(strcmp(sourceIp, dip[j]) == 0 && strcmp(destIp, sip[j]) == 0)	{
					flag = 1;
					table[j]++;
				}
			}

			if(flag == 0)	{

				strcpy(sip[i], sourceIp);
				strcpy(dip[i], destIp);
				table[i]++;
				i++;
			}
		}

		ip++;

		if (ipHeader->ip_p == IPPROTO_TCP) {

			tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

			sourcePort = ntohs(tcpHeader->source);
			destPort = ntohs(tcpHeader->dest);

			data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
			dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));

			printf("========== TCP ==========\n");
			printf("%s:%d -> %s:%d\n", sourceIp, sourcePort, destIp, destPort);
			printf("Recieved at ... %s", ctime((const time_t*)&(hdr->ts.tv_sec)));
		}

		if (ipHeader->ip_p == IPPROTO_UDP)	{

			sourcePort = ntohs(tcpHeader -> source);
			destPort = ntohs(tcpHeader -> dest);

			printf("========== UDP ==========\n");
			printf("%s:%d -> %s:%d\n", sourceIp, sourcePort, destIp, destPort);
			printf("Recieved at ... %s", ctime((const time_t*)&(hdr->ts.tv_sec)));
		}
	}
}
