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
#include <thread>
#include "../src/utils/MutexedQueue.h"

using namespace std;

class MNPacket
{
	public:
	void* msg;
	int len;
	MNPacket(void* msg, int len) {
		this->len = len;
		this->msg = malloc(len);
		memcpy(this->msg, msg, len);
	};

	~MNPacket() {
		delete[] msg;
	}
};

// class Multinet
// {
// public:
// 	Multinet();

// 	int bind(int port);
	
// 	int setInterface(char* interface);

// 	bool setDstAddress(int index, string addr, int port);

// 	int send(void* msg, size_t len);

// 	int recv(void* buf, int len);

// 	~Multinet();
	
// private:
// 	int UDPSocket;
// 	int UDPSocket2;
// 	sockaddr_in dstAddr[2];
// 	socklen_t dstAddrSize[2];
// 	// SOCKADDR_IN lastSrcAddr = { 0 };
// 	// int srcAddrSize = sizeof lastSrcAddr;

// 	MutexedQueue<MNPacket*> outgoingPackets;
// 	MutexedQueue<MNPacket*> incomingPackets;

// 	static void writing_loop(int index, Multinet*);
// 	static void reading_loop(int index, Multinet*);
	
// 	thread * firstSendThread;
// 	thread * secondSendThread;

// 	thread * firstRecvThread;
// 	thread * secondRecvThread;
// 	friend void printInfo(Multinet* m);
// };

#endif