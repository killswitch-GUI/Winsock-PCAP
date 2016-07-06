#pragma once
// winsock-native-pcap.cpp : Defines the exported functions for the DLL application.
//
#include "Winsock-pipe.h"
#include "stdafx.h"
#include <iostream>
#include <winsock2.h>
#include <fstream>
#include <time.h>

#define MAX_HOSTNAME_LAN 255
#define MAX_ADDR_LEN 9
#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1) //set the card into promiscious mode


/*
NOTE: You can not use the std::thread libary
with winssock, this will raise error 10022 on 
the recv() call. After trouble shooting 
this issue it turns out that std::thread calls
bind() as well to create a thread which will destroy 
your namespace!

DO NOT global std namespace!
*/
// Use std namespace for this project
extern int pill;

int winsockPcap();
int parse(char *buf, int packetSize);
int writeRawPacketCapture(char *buf, int packetSize);
int checkPacketSize(char *buf);
int writePcapHeader(char *fileName);
int writePcapPacket(char *buf, char *fileName, int packetSize, int totalLength);
bool filterPort(char *buf, int port);
bool filterIp(char *buf, int ip);
int printPacket(char *buf, int packetSize);
int printPacketData(char *buf, int packetSize, int outSize);
int parseTCP(char *buf, int iHeaderLen, int packetSize);
int parseUDP(char *buf, int iHeaderLen, int packetSize);
int parseICMP(char *buf, int iHeaderLen, int packetSize);
int currentTime();
int currentTimeHighRes();
int buildFCS(char *buf, int packetSize);
unsigned int reverse(unsigned x); // CRC32A compute
unsigned int crc32a(unsigned char *message); // CRC32A compute


// http://stackoverflow.com/questions/7309773/c-writing-structs-to-a-file-pcap
typedef struct pcap_hdr_s {
	uint32_t magic_number;   /* magic number */
	uint16_t version_major;  /* major version number */
	uint16_t version_minor;  /* minor version number */
	int32_t  thiszone;       /* GMT to local correction */
	uint32_t sigfigs;        /* accuracy of timestamps */
	uint32_t snaplen;        /* max length of captured packets, in octets */
	uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
	uint32_t ts_sec;         /* timestamp seconds */
	uint32_t ts_usec;        /* timestamp microseconds */
	uint32_t incl_len;       /* number of octets of packet saved in file */
	uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

typedef struct ethernet_hdr_s {
	uint8_t dst[6];    /* destination host address */
	uint8_t src[6];    /* source host address */
	uint16_t type;     /* IP? ARP? RARP? etc */
} ethernet_hdr_t;

typedef struct crc32a_hdr_s {
	uint8_t dst[6];    /* destination host address */
	uint8_t src[6];    /* source host address */
	uint16_t type;     /* IP? ARP? RARP? etc */
	uint16_t length;   /* The length of the packet */
} crc32a_hdr_t;

typedef struct ipheader {
	unsigned char ihl : 4, version : 4;  // <- 4 bits wide only
										 //unsigned char h_lenver; //IP Version
	unsigned char tos; // Type of service
	unsigned short total_len; // IP header length
	unsigned short ident;
	unsigned short frag_and_flags;
	unsigned char ttl; // Packet Time-to-Live
	unsigned char proto; // Next protocol
	unsigned short checksum;
	unsigned int sourceIP; // Source IP addr
	unsigned int destIP; // Dest IP addr
}IP_HDR;

// TCP header
typedef struct tcp_header {
	unsigned short source_port; // source port
	unsigned short dest_port; // destination port
	unsigned int sequence; // sequence number - 32 bits
	unsigned int acknowledge; // acknowledgement number - 32 bits

	unsigned char ns : 1; //Nonce Sum Flag Added in RFC 3540.
	unsigned char reserved_part1 : 3; //according to rfc
	unsigned char data_offset : 4; /*The number of 32-bit words in the TCP header.
								   This indicates where the data begins.
								   The length of the TCP header is always a multiple
								   of 32 bits.*/

	unsigned char fin : 1; //Finish Flag
	unsigned char syn : 1; //Synchronise Flag
	unsigned char rst : 1; //Reset Flag
	unsigned char psh : 1; //Push Flag
	unsigned char ack : 1; //Acknowledgement Flag
	unsigned char urg : 1; //Urgent Flag

	unsigned char ecn : 1; //ECN-Echo Flag
	unsigned char cwr : 1; //Congestion Window Reduced Flag

						   ////////////////////////////////

	unsigned short window; // window
	unsigned short checksum; // checksum
	unsigned short urgent_pointer; // urgent pointer
} TCP_HDR;

// UDP Header
typedef struct udp_hdr
{
	unsigned short source_port; // Source port no.
	unsigned short dest_port; // Dest. port no.
	unsigned short udp_length; // Udp packet length
	unsigned short udp_checksum; // Udp checksum (optional)
} UDP_HDR;

typedef struct icmp_hdr
{
	BYTE type; // ICMP Error type
	BYTE code; // Type sub code
	USHORT checksum;
	USHORT id;
	USHORT seq;
} ICMP_HDR;

// Adapted from wireshark text2pcsap CRC compute
typedef struct crc32_s { /* pseudo header for checksum calculation */
	uint32_t src_addr;
	uint32_t dest_addr;
	uint8_t  zero;
	uint8_t  protocol;
	uint16_t length;
} crc32_t;

int winsockPcap()
{
	DWORD dwBytesRet;
	unsigned int optval = 1;
	char RecvBuf[65535] = { 0 };
	char* fileName = "Debug.pcap";
	WSAData version;        //We need to check the version.
	WORD mkword = MAKEWORD(2, 2);
	int what = WSAStartup(mkword, &version);
	if (what != 0) {
		std::cout << "This version is not supported! - \n" << WSAGetLastError() << std::endl;
	}
	else {
		std::cout << "[*] WSAstartup is good!" << std::endl;
	}

	SOCKET u_sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (u_sock == INVALID_SOCKET)
		std::cout << "[!] Creating socket fail\n";

	else
		std::cout << "[*] Created sniffer socket!\n";

	//Setup recvive function for packets
	char FAR name[MAX_HOSTNAME_LAN];
	gethostname(name, MAX_HOSTNAME_LAN);

	struct hostent FAR * pHostent;
	pHostent = (struct hostent *)malloc(sizeof(struct hostent));
	pHostent = gethostbyname(name);
	SOCKADDR_IN sa;
	sa.sin_family = AF_INET;
	sa.sin_port = htons(6000);

	memcpy(&sa.sin_addr.S_un.S_addr, pHostent->h_addr_list[0], pHostent->h_length);
	bind(u_sock, (SOCKADDR *)&sa, sizeof(sa));
	WSAIoctl(u_sock, SIO_RCVALL, &optval, sizeof(optval), NULL, 0, &dwBytesRet, NULL, NULL);
	// Setup pcap file for writing
	if (writePcapHeader(fileName)) {
		// Value for packet header location
		int capErrors = 0;
		int maxcapErrors = 200; // will be used to prevent thrashing
		char ipAddress[] = "0";
		int ipAddr = inet_addr(ipAddress);
		int filterPortNumber = 0;
		int dataSize = 0;
		int packetCount = 0;
		int maxPacketCount = 1000000;
		int fileSize = 0;
		int maxFileSize = 1 * 1024 * 1024; //In MB format
		int packetOut = 0;
		bool enablePoisonPill = true;
		if (enablePoisonPill) {
			bool result = threadedPipe(); // Call pipe thread from Winsock-pipe.h
			if (result) {
				std::wcout << "[*] Threaded pipe server launched!" << std::endl;
			}
			else {
				std::wcout << "[*] Threaded pipe failed to launch!" << std::endl;
				// we should fail safe here and exit?
				// pill will be set to 1 and cap will hang
				return 1;
			}
		}
		bool stayAlive = true;
		while (packetCount < maxPacketCount && stayAlive) {
			// poison pill checks
			if (enablePoisonPill) {
				switch (pill) {
					std::cout << (int)pill << std::endl;
					case 0 : 
						//0 = stop - dont write / output data(pause)
						Sleep(1 * 1000);
						continue;
					case 1 :
						//1 = star - starts the cappture / continue
						break;
					case 2 :
						//2 = restart - restart and rebuild files
						writePcapHeader(fileName); // reset the output data
						packetCount = 0;
						dataSize = 0;
						pill = 1; // return to a start state
						break;
					case 3 :
						//3 = exit - set poison pill / kill thread main will exit
						stayAlive = false;
				}
			}
			int get = recv(u_sock, RecvBuf, sizeof(RecvBuf), 0);
			if (get == SOCKET_ERROR) {
				std::cout << "Error in Receiving: " << WSAGetLastError() << std::endl;
			}
			if (get > 0) {
				if (filterPortNumber) {
					if (!filterPort(RecvBuf, filterPortNumber)) {
						continue;
					}
				}
				if (ipAddr > 0) {
					if (!filterIp(RecvBuf, ipAddr)) {
						continue;
					}
				}
				dataSize = get + 13; // Ethernet header is 14, stack starts at 0
									 // add in the fake Ethernet header size
									 //writeRawPacketCapture(RecvBuf, get);
				writePcapPacket(RecvBuf, fileName, dataSize, get);
				if (packetOut) {
					printPacketData(RecvBuf, get, dataSize);
					parse(RecvBuf, get);
					printPacket(RecvBuf, get);
				}
			}
			// Add in global and packet headers
			fileSize += dataSize + 40;
			if (fileSize > maxFileSize) {
				std::wcout << "[!] Max file size reached: " << maxFileSize << std::endl;
				break;
			}
			packetCount = packetCount + 1;
		}
	}
	return 0;
}

// Check if packet size is to large
int checkPacketSize(char *buf) {
	int iTotalLength;
	IP_HDR *pIpheader;
	pIpheader = (IP_HDR *)buf;
	iTotalLength = pIpheader->total_len;
	if (iTotalLength > 65535) {
		// If over packet size drop packet, return False
		return 0;
	}
	else {
		// Under limit return True
		return 1;
	}
}

// Write Packet to disk in .pcap format
int writePcapHeader(char *fileName) {
	std::ofstream fileout(fileName, std::ios::binary);
	// build pcap format global header
	// https://wiki.wireshark.org/Development/LibpcapFileFormat
	pcap_hdr_s fileHeader;
	// Set file format itself and the byte ordering
	fileHeader.magic_number = 0xa1b2c3d4;
	fileHeader.version_major = 2;
	fileHeader.version_minor = 4;
	// UTC Timezone
	fileHeader.thiszone = 0;
	// Accuracy of the capture
	fileHeader.sigfigs = 0;
	fileHeader.snaplen = 0x040000;
	// http://www.tcpdump.org/linktypes.html
	// 1 = Ethernet LL
	fileHeader.network = 1;
	// write to stream
	fileout.write(reinterpret_cast<const char*>(&fileHeader),
		sizeof fileHeader);
	fileout.close();
	std::cout << "[*] PCAP global file header created: " << fileName << std::endl;
	return 1;
}

// write text log of packets
int writeRawPacketCapture(char *buf, int packetSize) {
	std::ofstream fileout("raw-cap.txt", std::ios::binary | std::ios::app);
	// Build fake temp Ethernet header
	ethernet_hdr_t ethernetHeader;
	for (int a = 0; a<7; a = a + 1) {
		ethernetHeader.dst[a] = 8;
		ethernetHeader.src[a] = 8;
	}
	ethernetHeader.type = 0x0000;
	fileout.write(reinterpret_cast<const char*>(&ethernetHeader),
		sizeof ethernetHeader);
	for (int i = 0; i < packetSize; i++) {
		fileout.write(&buf[i], sizeof(buf));
	}
	fileout.close();
	return true;
}

// Write the packet header and packet to .pcap
int writePcapPacket(char *buf, char *fileName, int packetSize, int totalLength) {
	std::ofstream fileout(fileName, std::ios::binary | std::ios::app);
	time_t ltime = currentTime();
	pcaprec_hdr_t packetHeader;
	packetHeader.ts_sec = ltime;
	packetHeader.ts_usec = currentTimeHighRes();
	packetHeader.incl_len = packetSize + 14;
	packetHeader.orig_len = packetSize + 14;
	// Build fake temp Ethernet header
	ethernet_hdr_t ethernetHeader;
	for (int a = 0; a<7; a = a + 1) {
		ethernetHeader.dst[a] = 8;
		ethernetHeader.src[a] = 8;
	}
	ethernetHeader.type = 0x0008; // Ethernet -> IP
			/*
			unsigned char *ucBuffer = (unsigned char*)&buf[0];
			char * val = reinterpret_cast<char*>(&ethernetHeader);
			unsigned char *ucBuffer2 = (unsigned char*)&val[0];
			int value = crc32a(ucBuffer2);
			wcout << "CRC: " << hex << value << endl;
			*/
	fileout.write(reinterpret_cast<const char*>(&packetHeader),
		sizeof packetHeader);
	fileout.write(reinterpret_cast<const char*>(&ethernetHeader),
		sizeof ethernetHeader);
	for (int i = 0; i < packetSize; i++) {
		fileout.write(&buf[i], 1);
	}
	fileout.close();
	return true;
}

// Filter on port, returns true or false
bool filterPort(char *buf, int port) {
	int iProtocol, iHeaderLen;
	IP_HDR *pIpheader;
	pIpheader = (IP_HDR *)buf;
	iProtocol = pIpheader->proto;
	iHeaderLen = pIpheader->ihl;
	if (iProtocol == IPPROTO_TCP) {
		unsigned short iphdrlen;
		iphdrlen = iHeaderLen * 4;
		TCP_HDR *pTcpHeader;
		// Advance the pointer to correct location
		pTcpHeader = (TCP_HDR*)(buf + iphdrlen);
		int tSourcePort = ntohs(pTcpHeader->source_port);
		int tDestPort = ntohs(pTcpHeader->dest_port);
		if (tDestPort == port || tSourcePort == port) {
			return true;
		}
		else {
			return false;
		}
	}
	if (iProtocol == IPPROTO_UDP) {
		unsigned short iphdrlen;
		iphdrlen = iHeaderLen * 4;
		UDP_HDR *pUdpHeader;
		// Advance the pointer to correct location
		pUdpHeader = (UDP_HDR*)(buf + iphdrlen);
		int uSourcePort = ntohs(pUdpHeader->source_port);
		int uDestPort = ntohs(pUdpHeader->dest_port);
		if (uDestPort == port || uSourcePort == port) {
			return true;
		}
		else {
			return false;
		}
	}
	else {
		// Catch all return false if not UDP/TCP
		return false;
	}
}

// Filter on ip, returns true or false
bool filterIp(char *buf, int ip) {
	int iProtocol, iHeaderLen;
	IP_HDR *pIpheader;
	pIpheader = (IP_HDR *)buf;
	int iSourceip = pIpheader->sourceIP;
	int iDestip = pIpheader->destIP;
	if (iSourceip == ip || iDestip == ip) {
		return true;
	}
	else {
		return false;
	}
}

// Parse packet aray
int parse(char *buf, int packetSize) {
	int iProtocol, iVersion, iHeaderLen, iService, iTotalLength, iSourceip, iDestip, iTtl;
	int iTTL;
	char *szSourceIP, *szDestIP;
	SOCKADDR_IN saSource, saDest;
	IP_HDR *pIpheader;
	pIpheader = (IP_HDR *)buf;
	//Check Proto
	iProtocol = pIpheader->proto;
	iVersion = pIpheader->version;
	iHeaderLen = pIpheader->ihl;
	iService = pIpheader->tos;
	iTotalLength = pIpheader->total_len;
	iSourceip = pIpheader->sourceIP;
	iDestip = pIpheader->destIP;
	iTtl = pIpheader->ttl;
	if (iSourceip) {
		saSource.sin_addr.s_addr = pIpheader->sourceIP;
		szSourceIP = inet_ntoa(saSource.sin_addr);
	}
	if (iDestip) {
		saDest.sin_addr.s_addr = pIpheader->sourceIP;
		szDestIP = inet_ntoa(saDest.sin_addr);
	}
	std::cout << "*-------------IP HEADER-------------*" << std::endl;
	std::cout << "| -- IP Version is: " << iVersion << std::endl;
	std::cout << "| -- IP Service is: " << iService << std::endl;
	std::cout << "| -- IP Header size is: " << ntohs(iTotalLength) << std::endl;
	std::wcout << "| -- IP Packet TTL : " << int(iTtl) << std::endl;
	std::wcout << "| -- IP Source IP : " << szSourceIP << std::endl;
	std::wcout << "| -- IP Dest IP : " << szDestIP << std::endl;
	std::wcout << "| -- IP Next Protocol: " << iProtocol << std::endl;

	if (iProtocol == IPPROTO_TCP) {
		parseTCP(buf, iHeaderLen, packetSize);
	}
	if (iProtocol == IPPROTO_UDP) {
		parseUDP(buf, iHeaderLen, packetSize);
	}
	if (iProtocol == IPPROTO_ICMP) {
		parseICMP(buf, iHeaderLen, packetSize);
	}
	return true;
}

// Parse a TCP packet from know start point
int parseTCP(char *buf, int iHeaderLen, int packetSize) {
	std::cout << "*-------------TCP HEADER-------------*" << std::endl;
	// IP Header is IHL * 4 for byte count
	unsigned short iphdrlen;
	iphdrlen = iHeaderLen * 4;
	TCP_HDR *pTcpHeader;
	// break array location
	pTcpHeader = (TCP_HDR*)(buf + iphdrlen);
	int tSourcePort = pTcpHeader->source_port;
	int tDestPort = pTcpHeader->dest_port;
	std::wcout << "| -- Source Port: " << ntohs(tSourcePort) << std::endl;
	std::wcout << "| -- Dest Port: " << ntohs(tDestPort) << std::endl;
	//wcout << "| -- TCP Packet Length: " << ntohs(uPacketLength) << endl;
	return true;
}

// parse UDP packet data and print to stdout
int parseUDP(char *buf, int iHeaderLen, int packetSize) {
	std::cout << "*-------------UDP HEADER-------------*" << std::endl;
	// IP Header is IHL * 4 for byte count
	unsigned short iphdrlen;
	iphdrlen = iHeaderLen * 4;
	UDP_HDR *pUdpHeader;
	// break array location
	pUdpHeader = (UDP_HDR*)(buf + iphdrlen);
	int uSourcePort = pUdpHeader->source_port;
	int uDestPort = pUdpHeader->dest_port;
	int uPacketLength = pUdpHeader->udp_length;
	int uCheckSum = pUdpHeader->udp_checksum;
	std::wcout << "| -- Source Port: " << ntohs(uSourcePort) << std::endl;
	std::wcout << "| -- Dest Port: " << ntohs(uDestPort) << std::endl;
	std::wcout << "| -- UDP Packet Length: " << ntohs(uPacketLength) << std::endl;
	std::wcout << "| -- UDP Checksum: " << ntohs(uCheckSum) << std::endl;
	return true;
}

// parse ICMP packet data and print to stdout
int parseICMP(char *buf, int iHeaderLen, int packetSize) {
	std::cout << "*------------ICMP HEADER------------*" << std::endl;
	// IP Header is IHL * 4 for byte count
	unsigned short iphdrlen;
	iphdrlen = iHeaderLen * 4;
	ICMP_HDR *pIcmpHeader;
	// break array location
	pIcmpHeader = (ICMP_HDR*)(buf + iphdrlen);
	int iCode = pIcmpHeader->code;
	int iCheckSum = pIcmpHeader->checksum;
	int iD = pIcmpHeader->id;
	int iSequence = pIcmpHeader->seq;
	std::wcout << "| -- Code: " << iCode << std::endl;
	std::wcout << "| -- Checksum: " << iCheckSum << std::endl;
	std::wcout << "| -- Id: " << iD << std::endl;
	std::wcout << "| -- Sequence: " << iSequence << std::endl;
	return true;
}

// print raw data of packet
int printPacket(char *buf, int packetSize) {
	std::cout << "*-------------ASCII DUMP------------*" << std::endl;
	for (int i = 0; i < packetSize; i++) {
		std::cout << buf[i];
	}
	std::cout << std::endl << std::endl;
	buf[packetSize] = 0; // Null-terminate the buffer
	std::cout << "*------------RAW HEX DUMP-----------*" << std::endl;
	buf[packetSize] = 0; // Null-terminate the buffer
	for (int i = 0; i < packetSize; i++) {
		std::cout << std::hex << (int)buf[i];
	}
	std::cout << std::endl << std::endl;
	return true;
}

// print packet meta data
int printPacketData(char *buf, int packetSize, int outSize) {
	std::cout << "*------------PACKET DATA-------------*" << std::endl;
	std::wcout << "| -- Bytes wrote: " << outSize << std::endl;
	std::wcout << "| -- Bytes Recv: " << packetSize << std::endl;
	return true;
}

// return current time in unix format
int currentTime() {
	time_t ltime;
	time(&ltime);
	struct tm* timeinfo = gmtime(&ltime);
	ltime = mktime(timeinfo);
	return ltime;
}

// return current time in high res ex (.345)
int currentTimeHighRes() {
	FILETIME time;
	SYSTEMTIME sysTime;
	GetSystemTimeAsFileTime(&time);
	FileTimeToSystemTime(&time, &sysTime);
	return sysTime.wMilliseconds;

}

/*
Bellow is the crc32a functions
http://www.hackersdelight.org/hdcodetxt/crc.c.txt
*/
// Reverses (reflects) bits in a 32-bit word.
unsigned reverse(unsigned x) {
	x = ((x & 0x55555555) << 1) | ((x >> 1) & 0x55555555);
	x = ((x & 0x33333333) << 2) | ((x >> 2) & 0x33333333);
	x = ((x & 0x0F0F0F0F) << 4) | ((x >> 4) & 0x0F0F0F0F);
	x = (x << 24) | ((x & 0xFF00) << 8) |
		((x >> 8) & 0xFF00) | (x >> 24);
	return x;
}

unsigned int crc32a(unsigned char *message) {
	int i, j;
	unsigned int byte, crc;

	i = 0;
	crc = 0xFFFFFFFF;
	while (message[i] != 0) {
		byte = message[i];            // Get next byte.
		byte = reverse(byte);         // 32-bit reversal.
		for (j = 0; j <= 7; j++) {    // Do eight times.
			if ((int)(crc ^ byte) < 0)
				crc = (crc << 1) ^ 0x04C11DB7;
			else crc = crc << 1;
			byte = byte << 1;          // Ready next msg bit.
		}
		i = i + 1;
	}
	return reverse(~crc);
}

// Chris set this up for PS 
__declspec (dllexport) int VoidFunc()
{
	winsockPcap();
	return 0;
}


