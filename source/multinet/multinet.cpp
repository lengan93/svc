#include "multinet.h"

void printInfo(Multinet* m) {
	cout << "UDPSocket: " << m->UDPSocket << endl;
	cout << "dstAddr0: " << inet_ntoa(m->dstAddr[0].sin_addr) <<":" << ntohs(m->dstAddr[0].sin_port) <<endl;
	cout << "dstAddrSize0: " << m->dstAddrSize[0] <<endl;
}

void Multinet::writing_loop(int index, Multinet* _this) {
	// cout <<"writing_loop thread " <<index <<" started" <<endl;
	
	// cout << "==== writing_loop ====" <<endl;
	// printInfo(_this);
	// cout << "==== /writing_loop ====" <<endl;

	while(1) {
		// cout << ",";
		MNPacket* packet = _this->outgoingPackets.dequeueWait(1000);
		if(packet != NULL) {
			::sendto(_this->UDPSocket, packet->msg, packet->len, 0, (sockaddr *)&(_this->dstAddr[index]), _this->dstAddrSize[index]);
			cout << "send a packet to " << inet_ntoa(_this->dstAddr[index].sin_addr) <<":" << ntohs(_this->dstAddr[index].sin_port) <<endl;
			// cout <<endl;
			// printInfo(_this);
			// cout <<endl;

			// switch(index) {
			// 	case 1:
			// 		::sendto(UDPSocket, packet->msg, packet->len, 0, (sockaddr *)&dstAddr, dstAddrSize);
			// 		break;
			// 	case 2:
			// 		::sendto(UDPSocket, packet->msg, packet->len, 0, (sockaddr *)&dstAddr2, dstAddrSize2);
			// 		break;
			// }
		}
		else {
			cout <<".";
		}
	}
}

void Multinet::reading_loop(int i, Multinet* _this) {
	
	// cout << "==== writing_loop ====" <<endl;
	// printInfo(_this);
	// cout << "==== /writing_loop ====" <<endl;

	int r;
	int len = 2000;
	int buf[len];
	while(1) {
		r = ::recvfrom(_this->UDPSocket, buf, len, 0, (sockaddr *)&(_this->dstAddr[i]), &(_this->dstAddrSize[i]));
		MNPacket * packet = new MNPacket(buf, r);
		_this->incomingPackets.enqueue(packet);
		cout << "recieve a packet from ";
	}
}

Multinet::Multinet() {
	UDPSocket = socket(AF_INET, SOCK_DGRAM, 0);
	UDPSocket2 = socket(AF_INET, SOCK_DGRAM, 0);

	dstAddrSize[0] = sizeof dstAddr[0];
	memset(&dstAddr[0], 0, sizeof dstAddrSize[0]);
	dstAddrSize[1] = sizeof dstAddr[1];
	memset(&dstAddr[1], 0, sizeof dstAddrSize[1]);

	// cout <<"Create threads" <<endl;
	firstSendThread = new thread(writing_loop, 0, this);
	secondSendThread = new thread(writing_loop, 1, this);
	
	// firstRecvThread = new thread(reading_loop, 0, this);
	// secondRecvThread = new thread(reading_loop, 1, this);
}

int Multinet::bind(int port) {
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

bool Multinet::setDstAddress(int index, string addr, int port) {
	memset(&dstAddr[index], 0, sizeof dstAddr[index]);
	dstAddr[index].sin_addr.s_addr = inet_addr(addr.c_str());
	dstAddr[index].sin_port = htons(port);
	dstAddr[index].sin_family = AF_INET;
	dstAddrSize[index] = sizeof dstAddr[index];
}

int Multinet::send(void* msg, size_t len) {
	// static int i = 0;
	// i = (i+1)%2;
	// cout << "sento " << inet_ntoa(dstAddr[i].sin_addr) <<":" << ntohs(dstAddr[i].sin_port) <<endl;
	// return ::sendto(UDPSocket, msg, len, 0, (sockaddr *)&dstAddr[i], dstAddrSize[i]);
	// cout << "==== send ====" <<endl;
	// printInfo(this);
	// cout << "==== /send ====" <<endl;

	MNPacket* packet = new MNPacket(msg, len);
	outgoingPackets.enqueue(packet);
	return 0;
}

int Multinet::recv(void* buf, int len) {
	int r = ::recvfrom(UDPSocket, buf, len, 0, (sockaddr *)&(dstAddr[0]), &(dstAddrSize[0]));
	memcpy(&dstAddr[1], &dstAddr[0], dstAddrSize[0]);
	// cout << endl;
	// printInfo(this);
	// cout << endl;
	cout << "recieve a packet" <<endl;
	cout << "recieve a packet from " << inet_ntoa(dstAddr[0].sin_addr) <<":" << ntohs(dstAddr[0].sin_port) <<endl;
	return r;

	// MNPacket* packet = _this->incomingPackets.dequeueWait(-1);
	// if(packet != NULL) {
	// 	memcpy(buf, packet->msg, packet->len);
	// 	int r = packet->len;
	// 	delete packet;
	// 	return r;
	// }
	// else {
	// 	return -1;
	// }
}

Multinet::~Multinet() {
	close(UDPSocket);

}