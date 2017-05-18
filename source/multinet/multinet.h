// A transmission protocol that can use serveral apdapers at the time

#ifndef __MULTINET__
#define __MULTINET__

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <iostream>
#include <sys/ioctl.h>
#include <net/if.h>
#include <cstring>

using namespace std;

class Multinet
{
public:
	Multinet();

	int bind(int port, const char* interface, const char* interface2);

	bool setDstAddress(string addr, int port);

	int send(const void* msg, size_t len);

	int recv(void* buf, int len);

	~Multinet();
	
private:
	int UDPSocket;
	int UDPSocket2;
	sockaddr_in dstAddr = { 0 };
	socklen_t dstAddrSize = sizeof dstAddr;
	// SOCKADDR_IN lastSrcAddr = { 0 };
	// int srcAddrSize = sizeof lastSrcAddr;

};

#endif