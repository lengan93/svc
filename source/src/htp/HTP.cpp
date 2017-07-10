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
		printf("[%d][%d] send packet %d(%2x)\n", getTime(), packet->getSessionID(), packet->getSequence(), packet->packet[0]);
	return r;
}

// TODO: prevent sequence prediction attack
bool HtpSocket::checkSequence(HtpPacket* packet) {

	HTPSession* session;
	uint32_t sessionID = packet->getSessionID();
	uint32_t seq = packet->getSequence();
	if(sessions.find(sessionID) == sessions.end()) {
		session = new HTPSession(sessionID, seq);
		session->setDstAddr(&packet->srcAddr, packet->srcAddrLen);
		sessions[sessionID] = session;
		return true;
	}

	session = sessions[sessionID];

	if(seq > session->getCurrentRecvSEQ()) {
		for (uint32_t i = session->getCurrentRecvSEQ()+1; i < seq; ++i)
		{
			session->missingPackets.insert(i);
		}
		session->setCurrentRecvSEQ(seq);
		return true;
	}
	else {
		auto it = session->missingPackets.find(seq);
		if(it == session->missingPackets.end()) {
			return false;
		}
		session->missingPackets.erase(it);
		return true;
	}
}

int HtpPacketCompare (HtpPacket* p1, HtpPacket* p2) {
    if(p1==NULL || p2==NULL) return -1;
    uint32_t s1 = p1->getSequence();
    uint32_t s2 = p2->getSequence();

    if(p1->getSessionID() == p2->getSessionID()) {
	    if(s1 < s2) return -1;
	    else if (s1 > s2) return 1;
	    else return 0;
	}
	else {
		return -1;
	}
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
			if(packet->isData()) {
				//-- what if the packet has a faked seq? 
				if(!_this->checkSequence(packet)) {
					_this->sendACK(packet);
					delete packet;
					break;
				}

				// print track log
				// if(PRINT_LOG)
					printf("[%d][%d] receive data packet %d(%d): \n", getTime(), packet->getSessionID(), packet->getSequence(), packet->packetLen);
				// printBuffer(packet->packet, HTP_PACKET_MINLEN);

				
				// print track log
				// printf("send ack for %d\n", packet->getSequence());
				_this->sendACK(packet);

				// printf("[%d] reading_loop wait\n", getTime());
				// _this->inComingBufferMutex.lock();
				// printf("[%d] reading_loop notified\n", getTime());
				_this->inComingQueue.enqueue(packet);
				// _this->inComingBufferMutex.unlock();
			}
			else if (packet->isACK()) {
				if(PRINT_LOG)
					printf("[%d][%d] received ACK of packet %d\n", getTime(), packet->getSessionID(), packet->getSequence());


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
			}
			else {
				if(PRINT_LOG){
					printf("[%d] receive unknown packet %d(%d): \n", getTime(), packet->getSequence(), packet->packetLen);
					printBuffer(packet->packet, HTP_PACKET_MINLEN);
				}
				delete packet;
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

void* HtpSocket::htp_retransmission_loop(void* args) {
	HtpSocket* _this = (HtpSocket*) args;

	while(1) {
		// _this->waitingACKListMutex.lock();
		HtpPacket* packet;
		if(_this->waitingACKPacketList.peakWait(&packet, 1000)) {
			if(packet->acked || packet->resend_times >= 5) {
				_this->waitingACKPacketList.dequeue();
				if(PRINT_LOG)
					printf("[%d] delete from buffer packet %d\n", getTime(), packet->getSequence());
				delete packet;
				// _this->waitingACKListMutex.unlock();
			}
			else if(packet->timeout()) {
				packet->setTimestamp();
				packet->resend_times++;
				// _this->waitingACKListMutex.unlock();
				if(PRINT_LOG)
					printf("[%d] resend ---------------- %d\n", getTime(), packet->getSequence());
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
		delete ack_packet;
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

HTPSession* findSession(unordered_map<uint32_t, HTPSession*> sessions, const struct sockaddr* addr) {
	
	for(auto i : sessions) {
		HTPSession* s = i.second;
		// cout << inet_ntoa(((sockaddr_in*)addr)->sin_addr) <<" - ";
		// cout << inet_ntoa(((sockaddr_in*)&(s->dstAddr))->sin_addr) <<endl;

		if( ((sockaddr_in*)addr)->sin_addr.s_addr == ((sockaddr_in*)&(s->dstAddr))->sin_addr.s_addr ) {
			return s;
		}
	}

	return NULL;
}

int HtpSocket::sendto(const void *msg, size_t len, int flags, const struct sockaddr *to, socklen_t tolen) {
	// return ::sendto(UDPSocket, msg, len, flags, to, tolen);
	if(msg == NULL || len == 0) {
		return -1;
	}

	// cout << inet_ntoa(((sockaddr_in*)to)->sin_addr) <<endl;
	HTPSession* session = findSession(sessions, to);
	if(session == NULL) {
		session = new HTPSession;
		session->setDstAddr((sockaddr_storage*)to, tolen);
		sessions[session->getID()] = session;
	}


	//create a htp frame
	// uint8_t* htp_frame = new uint8_t[HTP_HEADER_LENGTH + len];
	// htp_frame[0] = HTP_DATA;
 	// memcpy(htp_frame + 1, &currentSeq, HTP_SEQUENCE_LENGTH);
	// memcpy(htp_frame + HTP_HEADER_LENGTH, msg, len);
	
	//create a htp packet
	HtpPacket* packet = new HtpPacket(HTP_HEADER_LENGTH + len);
	packet->packet[0] = HTP_DATA;
	packet->setBody(msg, len);
	packet->setDstAddr((sockaddr_storage*)to, tolen);
	packet->setSequence(session->getCurrentSendSEQ()+1);
	packet->setSessionID(session->getID());

	session->setCurrentSendSEQ(packet->getSequence());

	// currentSeq++;
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
		HTPSession* session = sessions[packet->getSessionID()];

		// printf("session=%d, seq=%d, leftside=%d\n",packet->getSessionID(),packet->getSequence(), session->getRecvWindowLeftSeq());
		// for(auto it : sessions) {
		// 	cout << "session=" << it.first << "leftside=" << it.second->getRecvWindowLeftSeq() <<endl;
		// }

		if(packet->getSequence() == session->getRecvWindowLeftSeq()) {
			session->setRecvWindowLeftSeq(packet->getSequence()+1);
			// printf("leftside=%d\n", session->getRecvWindowLeftSeq());

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
			if(!session->reorganizeBuffer.empty()){
				auto it = session->reorganizeBuffer.begin();
				HtpPacket* pkt = *it;
				if(pkt->getSequence() != session->getRecvWindowLeftSeq()) {
					session->reorganizeBuffer.insert(packet);
					inComingQueue.dequeue();
				}
				else {
					session->setRecvWindowLeftSeq(pkt->getSequence()+1);
					r = pkt->packetLen - HTP_HEADER_LENGTH;
					memcpy(buf, pkt->packet + HTP_HEADER_LENGTH, r);
					*fromlen = pkt->srcAddrLen;
					memset(from, 0, sizeof(*from));
					memcpy(from, &(pkt->srcAddr), pkt->srcAddrLen);

					recvCounter++;
					// printf("%dth received, seq=%d\n", ++recvCounter, packet->getSequence());
					session->reorganizeBuffer.erase(it);
					delete pkt;
				}
			}
			else {
				session->reorganizeBuffer.insert(packet);
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