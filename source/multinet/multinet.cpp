#include "multinet.h"

Multinet::Multinet() {
	UDPSocket = socket(AF_INET, SOCK_DGRAM, 0);
	UDPSocket2 = socket(AF_INET, SOCK_DGRAM, 0);
}

int Multinet::bind(int port, const char* interface, const char* interface2) {
	struct sockaddr_in localAddress = {0};
    localAddress.sin_family = AF_INET;
    localAddress.sin_port = htons(port);
	localAddress.sin_addr.s_addr = htonl(INADDR_ANY); 
	
	int rs = ::bind(UDPSocket, (struct sockaddr*) &localAddress, sizeof(localAddress));
	
	return rs;
}

int Multinet::setInterface(char* interface) {

	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), interface);
	return setsockopt(UDPSocket, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr));

	// int rs = 1;

	// for(char* interface : interfaces) {
	// 	rs *= ::bind(UDPSocket, (struct sockaddr*) &localAddress, sizeof(localAddress));

	// }

	// int rs2 = ::bind(UDPSocket2, (struct sockaddr*) &localAddress, sizeof(localAddress));

	// snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), interface2);
	// if (setsockopt(UDPSocket2, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
	//     return -1;
	// }
}

bool Multinet::setDstAddress(string addr, int port) {
	dstAddr.sin_addr.s_addr = inet_addr(addr.c_str());
	dstAddr.sin_port = htons(port);
	dstAddr.sin_family = AF_INET;
	dstAddrSize = sizeof addr;
}

int Multinet::send(const void* msg, size_t len) {
	return ::sendto(UDPSocket, msg, len, 0, (sockaddr *)&dstAddr, dstAddrSize);
}

int Multinet::recv(void* buf, int len) {
	return ::recvfrom(UDPSocket, buf, len, 0, (sockaddr *)&dstAddr, &dstAddrSize);
}

Multinet::~Multinet() {
	close(UDPSocket);
}