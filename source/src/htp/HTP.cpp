#include "HTP.h"

#include <stdio.h> //used to print the debug information, will be removed later
#include "../utils/utils-functions.h"

/*
TODO: retransmission timeout, set a timeout for every important packet, so that the sender will
resend the packet if it doesn't receive the ack after pass the timeout
*/

#define PRINT_LOG true

HtpSocket::HtpSocket() throw(){
	if(PRINT_LOG)
		printf("default constructor\n");

	UDPSocket = socket(AF_INET, SOCK_DGRAM, 0);
	// currentSeq = 0;
}

HtpSocket::HtpSocket(in_port_t localPort) throw() : HtpSocket() {
	if(PRINT_LOG)
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

	// if (pthread_create(&htp_writing_thread, &attr, htp_writing_loop, this) != 0){
	// 	throw;
	// }

	if (pthread_create(&htp_retransmission_thread, &attr, htp_retransmission_loop, this) != 0){
		throw;
	}

	// if (pthread_create(&htp_ack_handle_thread, &attr, htp_ack_handler, this) != 0){
	// 	throw;
	// }
}

// HtpSocket::HtpSocket(size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {

// }

int HtpSocket::sendPacket(HtpPacket* packet) {
	int r;
	sendMutex.lock();
	r = ::sendto(this->UDPSocket, packet->packet, packet->packetLen, 0, 
					(sockaddr*) &(packet->dstAddr), packet->dstAddrLen);
	sendMutex.unlock();
	if(PRINT_LOG)
		printf("[%d] send packet %d(%2x)\n", getTime(), packet->getSequence(), packet->packet[0]);
	return r;
}

// TODO: prevent sequence prediction attack
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

int HtpPacketCompare (HtpPacket* p1, HtpPacket* p2) {
    if(p1==NULL || p2==NULL) return -1;
    uint32_t s1 = p1->getSequence();
    uint32_t s2 = p2->getSequence();

    if(s1 < s2) return -1;
    else if (s1 > s2) return 1;
    else return 0;
}

void* HtpSocket::htp_reading_loop(void* args) {
	//TODO: listen to the socket and enqueue every packet received to incoming queue

	if(PRINT_LOG)
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
					// if(PRINT_LOG)
						printf("[%d] receive data packet %d(%d): \n", getTime(), packet->getSequence(), packet->packetLen);
					// printBuffer(packet->packet, HTP_PACKET_MINLEN);

					// printf("[%d] reading_loop wait\n", getTime());
					// _this->inComingBufferMutex.lock();
					// printf("[%d] reading_loop notified\n", getTime());
					_this->inComingQueue.enqueue(packet);
					// _this->inComingBufferMutex.unlock();

					// if(!packet->isEncrypted()) {
						// print track log
						// printf("send ack for %d\n", packet->getSequence());
						_this->sendACK(packet);
					// }

					break;

				case HTP_ACK:
					// printf("%d sent success\n", packet->getSequence());
					// _this->receivedACKQueue.enqueue(packet);

					if(PRINT_LOG)
						printf("[%d] received ACK of packet %d\n", getTime(), packet->getSequence());


					/* TODO: remove the packet acked in the waiting queue */
					// _this->waitingACKListMutex.lock();
					{
						auto tmp = _this->waitingACKPacketList.find(packet, &HtpPacketCompare); 
						if(tmp != NULL) {
							tmp->acked = true;
							_this->successReceivedPackets++;
						}
					}
					// _this->waitingACKListMutex.unlock();

					delete packet;

					break;

				case HTP_NACK:
					break;

				default:
					if(PRINT_LOG){
						printf("[%d] receive unknown packet %d(%d): \n", getTime(), packet->getSequence(), packet->packetLen);
						printBuffer(packet->packet, HTP_PACKET_MINLEN);
					}
					break;
			}							
		}
		else {
			delete packet;
			if(PRINT_LOG)
				printf("drop a packet with invalid length\n");
		}

	// int r = ::recvfrom(UDPSocket, htp_frame, frame_len, flags, from, fromlen);
	}
}

// void* HtpSocket::htp_writing_loop(void* args) {
// 	//TODO: send every packet in the outgoing queue to its destination
// 	// uint8_t* htp_frame;

// 	if(PRINT_LOG)
// 		printf("writing thread created\n");

// 	HtpSocket* _this = (HtpSocket*) args;

// 	HtpPacket* packet;
// 	while(1) {
// 		// packet = _this->outGoingPackets.dequeueWait(1000);
// 		// if(packet != NULL) {
// 		_this->outGoingSetMutex.lock();
// 		if(!_this->outGoingPackets.empty()) {
// 			// packet = *(_this->outGoingPackets.begin());
// 			// _this->outGoingPackets.erase(packet);
// 			set<HtpPacket*, HtpPacketComparator>::iterator it = _this->outGoingPackets.begin();
// 			packet = *it;
// 			if(packet != NULL) {
// 				_this->outGoingPackets.erase(it);
// 				_this->outGoingSetMutex.unlock();

// 				// print track log
// 				if(PRINT_LOG)
// 					printf("[%d] send packet %d\n", getTime(), packet->getSequence());
// 				// printBuffer(packet->packet, HTP_PACKET_MINLEN);

// 				if(packet->isData() && packet->nolost()) {
// 					packet->setTimestamp();
// 					// if(packet->timer == nullptr) {
// 					// 	void* args[] = {_this, packet};
// 					// 	Timer *timer = new Timer(htp_retransmission_timeout_handler, args);
// 					// 	packet->setTimer(timer);
// 					// 	packet->timer->start(true);
// 					// }
// 					// else {
// 					// 	packet->timer->stop();
// 					// 	packet->timer->start(true);
// 					// }
// 				}

// 				::sendto(_this->UDPSocket, packet->packet, packet->packetLen, 0, 
// 					(sockaddr*) &(packet->dstAddr), packet->dstAddrLen);
// 				// if(packet->isData()) {
// 				// 	_this->waitingACKPacketList.push_back(packet);
// 				// }
// 				if(!packet->nolost()) {
// 					delete packet;
// 				}
// 			}
// 			else {
// 				_this->outGoingSetMutex.unlock();
// 				printf("wtf\n");
// 			}
// 		}
// 		else {
// 			_this->outGoingSetMutex.unlock();
// 		}
// 	}
// }


void* HtpSocket::htp_retransmission_loop(void* args) {
	HtpSocket* _this = (HtpSocket*) args;

	while(1) {
		// _this->waitingACKListMutex.lock();
		HtpPacket* packet;
		if(_this->waitingACKPacketList.peakWait(&packet, 1000)) {
			if(packet->acked || packet->resend_times >= 5) {
				_this->waitingACKPacketList.dequeue();
				if(PRINT_LOG)
					printf("delete from buffer packet %d\n", packet->getSequence());
				delete packet;
				// _this->waitingACKListMutex.unlock();
			}
			else if(packet->timeout()) {
				packet->setTimestamp();
				packet->resend_times++;
				// _this->waitingACKListMutex.unlock();
				if(PRINT_LOG)
					printf("resend ---------------- %d\n", packet->getSequence());
				// _this->outGoingSetMutex.lock();
				// _this->outGoingPackets.insert(packet);
				// _this->outGoingSetMutex.unlock();
				_this->sendPacket(packet);
				_this->resendPackets++;
			}
			else {
				// _this->waitingACKListMutex.unlock();
			}
		}
		else {
			// _this->waitingACKListMutex.unlock();
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
		// outGoingSetMutex.lock();
		// this->outGoingPackets.insert(ack_packet);
		// outGoingSetMutex.unlock();
		this->sendPacket(ack_packet);
	}
}

void HtpSocket::sendNACK(uint32_t seq, const struct sockaddr *to, socklen_t tolen) {
	this->missingPackets.insert(seq);
}


//======== HTP INTERFACE ==========
int HtpSocket::bind(struct sockaddr *my_addr, socklen_t addrlen) {
	if(PRINT_LOG)
		printf("htp_bind\n");
	return ::bind(UDPSocket, my_addr, addrlen);
}

int HtpSocket::close() {
	if(PRINT_LOG)
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

	sendCounter++;
	// printf("packet %d sent\n", packet->getSequence());

	// sentQueue.enqueue(htp_frame);
	int r = this->sendPacket(packet);

	/*check if the packet requires delivery ganrantee*/
	if(packet->nolost()) {
		// waitingACKPacketList.enqueue(packet);

		// set timestamp here to prevent instant retransmission
		packet->setTimestamp();

		// waitingACKListMutex.lock();
		waitingACKPacketList.enqueue(packet);
		// waitingACKPacketList.insert(packet);
		// waitingACKListMutex.unlock();
	}
	else {
		delete packet;		
	}
	//enqueue the packet to the outgoing queue
	// outGoingSetMutex.lock();
	// outGoingPackets.insert(packet);
	// outGoingSetMutex.unlock();
	return r;
}

int HtpSocket::recvfrom(void *buf, int len, unsigned int flags, struct sockaddr *from, socklen_t *fromlen) {
	// return ::recvfrom(UDPSocket, buf, len, flags, from, fromlen);

	// TODO: get the first data packet from the incoming queue

	// printf("htp_recvfrom\n");
	// static int recvCounter = 0;
	static bool track = false;

	int r = 0;
	// if(track)
		// printf("[%d] recvfrom wait\n", getTime());
	// inComingBufferMutex.lock();
	// if(track)
		// printf("[%d] recvfrom notified\n", getTime());
	HtpPacket* packet = NULL;
	inComingQueue.peakWait(&packet, 1000);
	// if(!inComingQueue.empty()) {
	// 	track = true;
	// 	set<HtpPacket*, HtpPacketComparator>::iterator it = (inComingQueue.begin());
	// 	HtpPacket* packet = *it;
	// 	if(packet->getSequence() != receiverWindowLeftSideSeq) {
	// 		// inComingBufferMutex.unlock();
	// 		printf(".\n\n");
	// 		return 0;
	// 	}
	// 	inComingQueue.erase(it);
	// 	// inComingBufferMutex.unlock();
	// 	receiverWindowLeftSideSeq++;

	if(packet != NULL && packet->isData()) {
		if(packet->getSequence() == receiverWindowLeftSideSeq) {
			receiverWindowLeftSideSeq++;
			r = packet->packetLen - HTP_HEADER_LENGTH;
			memcpy(buf, packet->packet + HTP_HEADER_LENGTH, r);
			*fromlen = packet->srcAddrLen;
			memset(from, 0, sizeof(*from));
			memcpy(from, &(packet->srcAddr), packet->srcAddrLen);

			recvCounter++;
			// printf("%dth received, seq=%d\n", ++recvCounter, packet->getSequence());
			inComingQueue.dequeue();
			delete packet;
		}
		else {
			if(!reordedPackets.empty()){
				auto it = reordedPackets.begin();
				HtpPacket* pkt = *it;
				if(pkt->getSequence() != receiverWindowLeftSideSeq) {
					reordedPackets.insert(packet);
					inComingQueue.dequeue();
				}
				else {
					receiverWindowLeftSideSeq++;
					r = pkt->packetLen - HTP_HEADER_LENGTH;
					memcpy(buf, pkt->packet + HTP_HEADER_LENGTH, r);
					*fromlen = pkt->srcAddrLen;
					memset(from, 0, sizeof(*from));
					memcpy(from, &(pkt->srcAddr), pkt->srcAddrLen);

					recvCounter++;
					// printf("%dth received, seq=%d\n", ++recvCounter, packet->getSequence());
					reordedPackets.erase(it);
					delete pkt;
				}
			}
			else {
				reordedPackets.insert(packet);
				inComingQueue.dequeue();
			}
			//TODO: buffer the packet and wait for the right order packet
		}
	}
	// }
	// else {
	// 	// inComingBufferMutex.unlock();
	// }
	
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
	if(PRINT_LOG)
		printf("htp_destructor\n");
	this->close();
}