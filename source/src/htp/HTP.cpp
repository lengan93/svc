#include "HTP.h"

#include <stdio.h> //used to print the debug information, will be removed later



HtpSocket::HtpSocket() throw(){
	printf("default constructor\n");

	UDPSocket = socket(AF_INET, SOCK_DGRAM, 0);


}

HtpSocket::HtpSocket(in_port_t localPort) throw() : HtpSocket() {
	printf("constructor with localPort\n");

	struct sockaddr_in localAddress = {0};
    localAddress.sin_family = AF_INET;
    localAddress.sin_port = htons(localPort);
	localAddress.sin_addr.s_addr = htonl(INADDR_ANY); 
	if( this->bind((struct sockaddr*) &localAddress, sizeof(localAddress)) ) {
		throw;
	}

	pthread_attr_t attr;
	pthread_attr_init(&attr);

	if (pthread_create(&htp_reading_thread, &attr, htp_reading_loop, this) != 0){
		throw;
	}

	if (pthread_create(&htp_writing_thread, &attr, htp_writing_loop, this) != 0){
		throw;
	}
}

HtpSocket::HtpSocket(size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {

}

void* HtpSocket::htp_reading_loop(void* args) {
	//TODO: listen to the socket and enqueue every packet received to incoming queue

	printf("reading thread created\n");

	HtpPacket* packet;
	int readbytes;

	HtpSocket* _this = (HtpSocket*) args;

	while(1) {
		packet = new HtpPacket();
		readbytes = ::recvfrom(_this->UDPSocket, packet->packet, HTP_DEFAULT_BUFSIZ, 0, 
			(sockaddr*) &(packet->srcAddr), &(packet->srcAddrLen));
		
		//TODO: Check if the received packet is data packet or control packet
		if(readbytes>HTP_HEADER_LENGTH) {
			packet->packetLen = readbytes;
		
			_this->inComingQueue.enqueue(packet);
		}
		else {
			delete packet;
		}

	// int r = ::recvfrom(UDPSocket, htp_frame, frame_len, flags, from, fromlen);
	}
}

void* HtpSocket::htp_writing_loop(void* args) {
	//TODO: send every packet in the outgoing queue to its destination
	// uint8_t* htp_frame;

	printf("writing thread created\n");

	HtpSocket* _this = (HtpSocket*) args;

	HtpPacket* packet;
	while(1) {
		if(_this->outGoingQueue.notEmpty()) {
			packet = _this->outGoingQueue.dequeueWait(1000);

			::sendto(_this->UDPSocket, packet->packet, packet->packetLen, 0, 
				(sockaddr*) &(packet->dstAddr), packet->dstAddrLen);
			// ::sendto(UDPSocket, htp_frame, len, flags, to, tolen);

			_this->sentQueue.enqueue(packet);
		}
	}
}

int HtpSocket::bind(struct sockaddr *my_addr, socklen_t addrlen) {
	printf("htp_bind\n");
	return ::bind(UDPSocket, my_addr, addrlen);
}

int HtpSocket::close() {
	printf("htp_close\n");
	return ::close(UDPSocket);
}

int HtpSocket::sendto(const void *msg, size_t len, int flags, const struct sockaddr *to, socklen_t tolen) {

	printf("htp_sento\n");

	//create a htp frame
	uint8_t* htp_frame = new uint8_t[HTP_HEADER_LENGTH + len];
	htp_frame[0] = 0x00;
 	memcpy(htp_frame + 1, &currentSeq, HTP_SEQUENCE_LENGTH);
	memcpy(htp_frame + HTP_HEADER_LENGTH, msg, len);

	//create a htp packet
	HtpPacket* packet = new HtpPacket(htp_frame, HTP_HEADER_LENGTH + len);
	packet->setDstAddr((sockaddr_storage*)to, tolen);
	
	// return ::sendto(UDPSocket, htp_frame, len, flags, to, tolen);

	//enqueue the packet to the outgoing queue
	outGoingQueue.enqueue(packet);

	// sentQueue.enqueue(htp_frame);
	return 0;
}

int HtpSocket::recvfrom(void *buf, int len, unsigned int flags, struct sockaddr *from, socklen_t *fromlen) {
	// TODO: get the first data packet from the incoming queue

	printf("htp_recvfrom\n");

	int r = 0;

	HtpPacket* packet = inComingQueue.dequeueWait(1000);

	if(packet != NULL) {
		r = packet->packetLen - HTP_HEADER_LENGTH;
		memcpy(buf, packet->packet + HTP_HEADER_LENGTH, r);
		*fromlen = packet->srcAddrLen;
		memset(from, 0, sizeof(*from));
		memcpy(from, &(packet->srcAddr), packet->srcAddrLen);
	}
	return r;

	// int frame_len = len + HTP_HEADER_LENGTH;
	// uint8_t* htp_frame = new uint8_t[frame_len];

	// int r = ::recvfrom(UDPSocket, htp_frame, frame_len, flags, from, fromlen);
	// if (r > HTP_HEADER_LENGTH) {
	// 	//check if it's data packet or control packet
	// 	memcpy(buf, htp_frame + HTP_HEADER_LENGTH, r - HTP_HEADER_LENGTH);
	// 	return r - HTP_HEADER_LENGTH;
	// }

	// return 0;
}

HtpSocket::~HtpSocket() {
	printf("htp_destructor\n");
	this->close();
}