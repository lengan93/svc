#include "HTP.h"

#include <stdio.h> //used to print the debug information, will be removed later
#include "../utils/utils-functions.h"

/*
TODO: update session ID in case the other side change IP address
*/

#define PRINT_LOG false

/* ======== utility functions ========= */
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

/* ========= HtpSocket methods ============ */
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
	if(PRINT_LOG && packet->isImportant())
		printf("[%d][%d] send packet %d(%2x)\n", getTime(), packet->getSessionID(), packet->getSequence(), packet->packet[0]);
	return r;
}


// TODO: prevent sequence prediction attack
bool HtpSocket::checkSequence(HtpPacket* packet) {

	HTPSession* session;
	uint32_t sessionID = packet->getSessionID();
	uint32_t seq = packet->getSequence();
	if(sessions.find(sessionID) == sessions.end()) {
		HTPSession * tmp = findSession(sessions, (sockaddr*) &packet->srcAddr);
		if(tmp != NULL) {

			cout << "update session for " << inet_ntoa(((sockaddr_in*)&packet->srcAddr)->sin_addr) <<endl;
			sessions.erase(tmp->getID());
			delete tmp;
		}
		session = new HTPSession(sessionID, seq);
		session->setDstAddr(&packet->srcAddr, packet->srcAddrLen);
		sessions[sessionID] = session;
		return true;
	}
	// this is the first packet of the session
	// TODO: use the HTP_START_SS bit 
	else if(seq == 1) {
		sessions[sessionID]->setCurrentRecvSEQ(0);
		sessions[sessionID]->setRecvWindowLeftSeq(1);
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
		
		if(packet->packetLen > 0) {
			if(packet->isData()) {
				if(packet->isImportant()) {
					if(packet->checkLength()) {
						if(!_this->checkSequence(packet)) {
							_this->sendACK(packet);
							printf("[%d][%d] reject packet %d(%d): \n", getTime(), packet->getSessionID(), packet->getSequence(), packet->packetLen);
							delete packet;
							continue;
						}

						// print track log
						if(PRINT_LOG)
							printf("[%d][%d] receive data packet %d(%d): \n", getTime(), packet->getSessionID(), packet->getSequence(), packet->packetLen);
						
						_this->inComingQueue.enqueue(packet);
						
						// print track log
						printf("send ack for %d\n", packet->getSequence());
						_this->sendACK(packet);
					}
					else {
						delete packet;
						if(PRINT_LOG)
							printf("drop a packet with invalid length\n");
					}
				}
				else { //non-important packet
					_this->inComingQueue.enqueue(packet);
				}
			}
			else if (packet->isACK()) {
				if(PRINT_LOG)
					printf("[%d][%d] received ACK of packet %d\n", getTime(), packet->getSessionID(), packet->getSequence());

				/* TODO: remove the packet acked in the waiting queue */
				{
					auto tmp = _this->waitingACKPacketList.find(packet, &HtpPacketCompare); 
					if(tmp != NULL) {
						tmp->acked = true;
						if(PRINT_LOG)
							printf("[%d][%d] ACK packet %d\n", getTime(), packet->getSessionID(), packet->getSequence());

						_this->successReceivedPackets++;
					}
				}

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
	int r = -1;

	if(msg == NULL || len == 0) {
		return r;
	}
	
	if((flags & HTP_IMPT) != 0) {

		HTPSession* session = findSession(sessions, to);
		if(session == NULL) {
			session = new HTPSession;
			session->setDstAddr((sockaddr_storage*)to, tolen);
			sessions[session->getID()] = session;
		}

		//create a htp packet
		HtpPacket* packet = new HtpPacket(HTP_HEADER_LENGTH + len);
		packet->setFlag(HTP_DATA|HTP_IMPT);		
		
		packet->setBody(msg, len);
		packet->setDstAddr((sockaddr_storage*)to, tolen);
		packet->setSequence(session->getCurrentSendSEQ()+1);
		packet->setSessionID(session->getID());

		session->setCurrentSendSEQ(packet->getSequence());

		sendCounter++;

		r = this->sendPacket(packet);

		// set timestamp here to prevent instant retransmission
		packet->setTimestamp();

		waitingACKPacketList.enqueue(packet);
	}
	else {
		HtpPacket* packet = new HtpPacket(1 + len);
		packet->setFlag(HTP_DATA);		
		
		memcpy(packet->packet + 1, msg, len);
		packet->packetLen = 1 + len;
		packet->setDstAddr((sockaddr_storage*)to, tolen);

		r = this->sendPacket(packet);

		delete packet;
	}

	return r;
}

int HtpSocket::recvfrom(void *buf, int len, unsigned int flags, struct sockaddr *from, socklen_t *fromlen) {
	// return ::recvfrom(UDPSocket, buf, len, flags, from, fromlen);

	static bool track = false;

	int r = 0;

	HtpPacket* packet = NULL;
	inComingQueue.peakWait(&packet, 1000);

	if(packet != NULL && packet->isData()) {
		if(packet->isImportant()) {
			HTPSession* session = sessions[packet->getSessionID()];

			if(packet->getSequence() == session->getRecvWindowLeftSeq()) {
				session->setRecvWindowLeftSeq(packet->getSequence()+1);
				printf("leftside=%d\n", session->getRecvWindowLeftSeq());

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
			}
		}
		else {
			r = packet->packetLen - 1;
			memcpy(buf, packet->packet + 1, r);
			*fromlen = packet->srcAddrLen;
			memset(from, 0, sizeof(*from));
			memcpy(from, &(packet->srcAddr), packet->srcAddrLen);
		}
	}
	return r;
}

HtpSocket::~HtpSocket() {
	if(PRINT_LOG)
		printf("htp_destructor\n");
	this->close();
}