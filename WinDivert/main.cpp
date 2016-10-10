#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include "windivert.h"
#include<WS2tcpip.h>
#include<map>
#pragma comment(lib, "Ws2_32.lib")
#define MAXBUF  0xFFFF
#define TCP 0x06
using namespace std;
void show_ipaddr(PWINDIVERT_IPHDR ip_header, PWINDIVERT_TCPHDR tcp_header);
typedef struct {
	WINDIVERT_IPHDR ip;
	WINDIVERT_TCPHDR tcp;
} TCPPACKET, *PTCPPACKET;

int __cdecl main(int argc, char **argv) {
	HANDLE handle, console;
	INT16 priority = 0;
	unsigned char packet[MAXBUF];
	char *target = "10.100.111.71"; // 보내는사람
	char *dest = "10.100.111.117";  // 프록시
	UINT packet_len;
	WINDIVERT_ADDRESS recv_addr, send_addr;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_TCPHDR tcp_header;
	UINT payload_len = 0;
	char *payload;
	payload = (char *)malloc(payload_len);
	TCPPACKET reset;
	PTCPPACKET pReset = &reset;
	map<string, string> m;
	map<string, string>::iterator iter;
	string str1, str2, tmp;
	inet_pton(AF_INET, target, &pReset->ip.SrcAddr);
	inet_pton(AF_INET, dest, &pReset->ip.DstAddr);
	console = GetStdHandle(STD_OUTPUT_HANDLE);
	handle = WinDivertOpen(argv[1], WINDIVERT_LAYER_NETWORK, 1000, 0);
	if (handle == INVALID_HANDLE_VALUE) {// WinDivertOpen(const char *filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags)
		if (GetLastError() == ERROR_INVALID_PARAMETER) {
			fprintf(stderr, "error: filter syntax error\n");
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n", GetLastError());
		exit(EXIT_FAILURE);
	}
	// MAIN LOOP
	while (1) {
		if (!WinDivertRecv(handle, packet, sizeof(packet), &recv_addr, &packet_len)) {
			fprintf(stderr, "warning: failed to read packet\n");
			continue;
		}
		WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL, NULL, NULL, &tcp_header, NULL, (PVOID *)payload, &payload_len);
		str1.clear(); str2.clear(); tmp.clear();
		if ((ip_header->SrcAddr == pReset->ip.SrcAddr) && ( ntohs(tcp_header->DstPort) == 80 )) { // 보내는 사람ip가 targetip이면
			str1 = to_string(ip_header->SrcAddr) + ',' + to_string(tcp_header->SrcPort);
			str2 = to_string(ip_header->DstAddr) + ',' + to_string(tcp_header->DstPort);
			m.insert(pair<string, string>(str1, str2));
			ip_header->DstAddr = pReset->ip.DstAddr;	// 목적지를 PROXY로 바꾸고
			tcp_header->DstPort = htons(8080);			// 포트 변경
			printf("[OUT] "); show_ipaddr(ip_header, tcp_header);
		}

		else if ((ip_header->SrcAddr == pReset->ip.DstAddr) && ( ntohs(tcp_header->SrcPort) == 8080)) {	
			tmp = to_string(ip_header->DstAddr) + ',' + to_string(tcp_header->DstPort);// 받는사람 PORT가 MAP에 있는 PORT와 일치하면 SrcAddr:Port, DstAddr을 바꿔준다
			for (iter = m.begin(); iter != m.end(); ++iter) {
				if ((*iter).first.compare(tmp)){
					ip_header->SrcAddr = stoi((*iter).second.substr(0, (*iter).second.find(',')));
					tcp_header->SrcPort = stoi((*iter).second.substr((*iter).second.find(','), (*iter).second.back()+1));
				}
			}
			printf("[I N] "); show_ipaddr(ip_header, tcp_header);
		}

		WinDivertHelperCalcChecksums((PVOID)packet, packet_len, 0);
		if (!WinDivertSend(handle, (PVOID)packet, packet_len, &send_addr, NULL))
			fprintf(stderr, "warning: failed to send reset (%d)\n", GetLastError());
	}
}

void show_ipaddr(PWINDIVERT_IPHDR ip_header, PWINDIVERT_TCPHDR tcp_header) {
	UINT8 *src_addr, *dst_addr;

	src_addr = (UINT8 *)&ip_header->SrcAddr;
	dst_addr = (UINT8 *)&ip_header->DstAddr;
	printf("");
	printf("ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u\n", src_addr[0], src_addr[1], src_addr[2], src_addr[3], dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
}