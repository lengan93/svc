#include "HTP.h"

#include <stdio.h> //used to print the debug information, will be removed later
#include "../utils/utils-functions.h"

/*
TODO: retransmission timeout, set a timeout for every important packet, so that the sender will
resend the packet if it does receive the ack after pass the timeout
*/

HtpSocket::HtpSocket() throw(){
	printf("default constructor\n");

	UDPSocket = socket(AF_INET, SOCK_DGRAM, 0);

	// currentSeq = 0;
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

	if (pthread_create(&htp_ack_handle_thread, &attr, htp_ack_handler, this) != 0){
		throw;
	}
}

// HtpSocket::HtpSocket(size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {

// }

bool HtpSocket::checkSequence(uint32_t seq) {
	if(seq > biggestSeq) {
		for (uint32_t i = biggestSeq+1; i < seq; ++i)
		{
			missingPackets.insert(i);
		}
		biggestSeq = seq;
		return true;
	}
	else {
		set<uint32_t>::iterator it = missingPackets.find(seq);
		if(it == missingPackets.end()) {
			return false;
		}
		missingPackets.erase(it);
		return true;
	}
}

void* HtpSocket::htp_reading_loop(void* args) {
	//TODO: listen to the socket and enqueue every packet received to incoming queue

	printf("reading thread created\n");

	HtpPacket* packet;
	uint32_t readbytes;

	HtpSocket* _this = (HtpSocket*) args;

	while(1) {
		packet = new HtpPacket();
		readbytes = ::recvfrom(_this->UDPSocket, packet->packet, HTP_DEFAULT_BUFSIZ, 0, 
			(sockaddr*) &(packet->srcAddr), &(packet->srcAddrLen));
		packet->packetLen = readbytes;
		
		if(packet->checkLength()) {
			
			switch (packet->packet[0]) {
				case HTP_DATA:
					
					//-- what if the packet has a faked seq? 
					if(!_this->checkSequence(packet->getSequence())) {
						_this->sendACK(packet);
						delete packet;
						break;
					}

					// print track log
					printf("receive data packet %d(%d): \n", packet->getSequence(), packet->packetLen);
					// printBuffer(packet->packet, HTP_PACKET_MINLEN);

					_this->inComingBufferMutex.lock();
					_this->inComingQueue.insert(packet);
					_this->inComingBufferMutex.unlock();

					// if(!packet->isEncrypted()) {
						// print track log
						// printf("send ack for %d\n", packet->getSequence());
						_this->sendACK(packet);
					// }

					break;

				case HTP_ACK:
					// printf("%d sent success\n", packet->getSequence());
					_this->receivedACKQueue.enqueue(packet);
					break;

				case HTP_NACK:
					break;
			}							
		}
		else {
			delete packet;
			printf("drop a packet with invalid length\n");
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
		// packet = _this->outGoingPackets.dequeueWait(1000);
		// if(packet != NULL) {
		_this->outGoingSetMutex.lock();
		if(!_this->outGoingPackets.empty()) {
			// packet = *(_this->outGoingPackets.begin());
			// _this->outGoingPackets.erase(packet);
			
			set<HtpPacket*, HtpPacketComparator>::iterator it = _this->outGoingPackets.begin();
			packet = *it;
			if(packet != NULL) {
				_this->outGoingPackets.erase(it);
				_this->outGoingSetMutex.unlock();

				// print track log
				printf("send packet %d\n", packet->getSequence());
				// printBuffer(packet->packet, HTP_PACKET_MINLEN);
				::sendto(_this->UDPSocket, packet->packet, packet->packetLen, 0, 
					(sockaddr*) &(packet->dstAddr), packet->dstAddrLen);
				// if(packet->isData()) {
				// 	_this->waitingACKPacketList.push_back(packet);
				// }
				if(!packet->nolost()) {
					delete packet;
				}
			}
			else {
				_this->outGoingSetMutex.unlock();
				printf("wtf\n");
			}
		}
		else {
			_this->outGoingSetMutex.unlock();
		}
	}
}

void* HtpSocket::htp_ack_handler(void* args) {
	HtpSocket* _this = (HtpSocket*) args;

	HtpPacket* ackPkt;
	HtpPacket* packet;
	uint32_t ack;
	uint32_t seq;
	ofstream* logfile = new ofstream("lostpacket.log");
	// char gap[10] = {0};
	while(1) {
		ackPkt = _this->receivedACKQueue.dequeueWait(1000);

		if(ackPkt != NULL) {
			ack = ackPkt->getSequence();
			// print track log
			printf("receive ack of %d\n", ack);

			// THIS ALGORITHM MIGHT BE WRONG
			
			_this->waitingACKListMutex.lock();
			std::list<HtpPacket*>::iterator pktIt=_this->waitingACKPacketList.begin(); 
			while(pktIt!=_this->waitingACKPacketList.end()) {
				packet = *pktIt;
				seq = packet->getSequence();
				if(ack == seq) {
					//-- check source address
					pktIt = _this->waitingACKPacketList.erase(pktIt);
					delete packet;
					_this->successReceivedPackets++;
					// print track log
					// printf("send success   %d\n", seq);
				}
				else if(ack > seq){
					//ack > seq : packet might be lost, resend it and go to the next packet
					_this->outGoingPackets.insert(packet);
					_this->resendPackets++;
					printf("resend ---------------- %d\n", seq);
					// pktIt = _this->waitingACKPacketList.erase(pktIt);
					// print track log
					// printf("lose packet           %d\n", seq);
					// logfile->write((char*)&seq, 4);
					// logfile->write((char*)packet->packet, packet->packetLen);
					// logfile->write(gap, 10);
					// logPacket(logfile, seq, packet->packet, packet->packetLen);

					pktIt++;
					continue;
				}
				else {
					//invalid ack
				}

				delete ackPkt;
				break;
			}
			_this->waitingACKListMutex.unlock();
		}
	}
}

/*
issue: how to detect it's sent from the right sender ??
*/
void HtpSocket::sendACK(HtpPacket* packet) {
	// return ;
	
	// print track log
	// printBuffer(packet->packet, HTP_PACKET_MINLEN);
	if(packet->checkLength()) {
		// print track log
		// printf("sending ack %d: \n", packet->getSequence());
		int ackLen = HTP_PACKET_MINLEN;
		uint8_t htp_frame[ackLen];
		htp_frame[0] = HTP_ACK;
		memcpy(htp_frame+1, packet->packet + 1, ackLen-1);

		HtpPacket* ack_packet = new HtpPacket(htp_frame, ackLen);
		ack_packet->setDstAddr(&(packet->srcAddr), packet->srcAddrLen);
		outGoingSetMutex.lock();
		this->outGoingPackets.insert(ack_packet);
		outGoingSetMutex.unlock();
	}
}

// void HtpSocket::sendACK(uint8_t* packet) {
// 	int ackLen = 2 + ENDPOINTID_LENGTH + SEQUENCE_LENGTH;
// 	uint8_t htp_frame[ackLen];
// 	htp_frame[0] = HTP_ACK;
// 	memcpy(htp_frame+2, packet + 2, ackLen-2);

// 	HtpPacket* ack_packet = new HtpPacket(htp_frame, ackLen);
// 	ack_packet->setDstAddr(&(packet->srcAddr), packet->srcAddrLen);
// 	this->outGoingPackets.enqueue(ack_packet);
// }

void HtpSocket::sendNACK(uint32_t seq, const struct sockaddr *to, socklen_t tolen) {
	this->missingPackets.insert(seq);
}


//======== HTP INTERFACE ==========
int HtpSocket::bind(struct sockaddr *my_addr, socklen_t addrlen) {
	printf("htp_bind\n");
	return ::bind(UDPSocket, my_addr, addrlen);
}

int HtpSocket::close() {
	printf("htp_close\n");
	return ::close(UDPSocket);
}

int HtpSocket::sendto(const void *msg, size_t len, int flags, const struct sockaddr *to, socklen_t tolen) {
	// return ::sendto(UDPSocket, msg, len, flags, to, tolen);

	if(msg == NULL || len == 0) {
		return -1;
	}
	// printf("htp_sento\n");

	//create a htp frame
	uint8_t* htp_frame = new uint8_t[HTP_HEADER_LENGTH + len];
	htp_frame[0] = HTP_DATA;
 	// memcpy(htp_frame + 1, &currentSeq, HTP_SEQUENCE_LENGTH);
	memcpy(htp_frame + HTP_HEADER_LENGTH, msg, len);
	
	// -- simple send
	// return ::sendto(UDPSocket, htp_frame, len+HTP_HEADER_LENGTH, flags, to, tolen);

	//create a htp packet
	HtpPacket* packet = new HtpPacket(htp_frame, HTP_HEADER_LENGTH + len);
	packet->setDstAddr((sockaddr_storage*)to, tolen);
	packet->setSequence(currentSeq);
	currentSeq++;

	/*check if the packet requires delivery ganrantee*/
	if(packet->nolost()) {
		// waitingACKPacketList.enqueue(packet);
		waitingACKListMutex.lock();
		waitingACKPacketList.push_back(packet);
		waitingACKListMutex.unlock();
	}
	//enqueue the packet to the outgoing queue
	outGoingSetMutex.lock();
	outGoingPackets.insert(packet);
	outGoingSetMutex.unlock();

	sendCounter++;
	// printf("packet %d sent\n", packet->getSequence());

	// sentQueue.enqueue(htp_frame);
	return 0;
}

int HtpSocket::recvfrom(void *buf, int len, unsigned int flags, struct sockaddr *from, socklen_t *fromlen) {
	// return ::recvfrom(UDPSocket, buf, len, flags, from, fromlen);

	// TODO: get the first data packet from the incoming queue

	// printf("htp_recvfrom\n");
	// static int recvCounter = 0;

	int r = 0;

	inComingBufferMutex.lock();
	if(!inComingQueue.empty()) {
		set<HtpPacket*, HtpPacketComparator>::iterator it = (inComingQueue.begin());
		HtpPacket* packet = *it;
		if(packet->getSequence() != receiverWindowLeftSideSeq) {
			inComingBufferMutex.unlock();
			return 0;
		}
		inComingQueue.erase(it);
		inComingBufferMutex.unlock();
		receiverWindowLeftSideSeq++;

		if(packet != NULL && packet->isData()) {
			r = packet->packetLen - HTP_HEADER_LENGTH;
			memcpy(buf, packet->packet + HTP_HEADER_LENGTH, r);
			*fromlen = packet->srcAddrLen;
			memset(from, 0, sizeof(*from));
			memcpy(from, &(packet->srcAddr), packet->srcAddrLen);

			recvCounter++;
			// printf("%dth received, seq=%d\n", ++recvCounter, packet->getSequence());

			delete packet;
		}
	}
	else {
		inComingBufferMutex.unlock();
	}
	
	return r;

	//-- simple receive
	// int frame_len = len + HTP_HEADER_LENGTH;
	// uint8_t* htp_frame = new uint8_t[frame_len];

	// int r = ::recvfrom(UDPSocket, htp_frame, frame_len, flags, from, fromlen);
	// if (r > HTP_HEADER_LENGTH) {
	// 	//check if it's data packet or control packet
	// 	memcpy(buf, htp_frame + HTP_HEADER_LENGTH, r - HTP_HEADER_LENGTH);
	// 	printf("r\n");
	// 	return r - HTP_HEADER_LENGTH;
	// }

	// return 0;
}

HtpSocket::~HtpSocket() {
	printf("htp_destructor\n");
	this->close();
}