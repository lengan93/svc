#ifndef __HTP_SESSION__
#define __HTP_SESSION__

class HTPSession
{
public:

	HTPSession() {
		srand(time(NULL));
		this->sessionID = rand();
		this->currentSendSEQ = 0;
		this->currentRecvSEQ = 0;
		this->recvWindowLeftSeq = 1;
		// printf("created session %d, leftside=%d\n", sessionID, recvWindowLeftSeq);
	}

	HTPSession(uint32_t id) {
		this->sessionID = id;
		this->currentSendSEQ = 0;
		this->currentRecvSEQ = 0;
		this->recvWindowLeftSeq = 1;
		// printf("created session %d, leftside=%d\n", sessionID, recvWindowLeftSeq);
	}

	HTPSession(uint32_t id, uint32_t begin) {
		this->sessionID = id;
		this->currentSendSEQ = 0;
		this->currentRecvSEQ = begin;
		this->recvWindowLeftSeq = begin;
		// printf("created session %d, leftside=%d\n", sessionID, recvWindowLeftSeq);
	}

	~HTPSession() {
		this->reorganizeBuffer.clear();
	}

	uint32_t getID() {
		return this->sessionID;
	}

	void setID(uint32_t id) {
		this->sessionID = id;
	}

	uint32_t getCurrentSendSEQ() {
		return this->currentSendSEQ;
	}

	void setCurrentSendSEQ(uint32_t seq) {
		this->currentSendSEQ = seq;
	}

	uint32_t getCurrentRecvSEQ() {
		return this->currentRecvSEQ;
	}

	void setCurrentRecvSEQ(uint32_t seq) {
		this->currentRecvSEQ = seq;
	}

	uint32_t getRecvWindowLeftSeq() {
		return this->recvWindowLeftSeq;
	}

	void setRecvWindowLeftSeq(uint32_t seq) {
		this->recvWindowLeftSeq = seq;
		// printf("session %d, set leftside=%d\n", sessionID, recvWindowLeftSeq);
	}

	void setDstAddr(const struct sockaddr_storage* dstAddr, socklen_t addrLen){
		memset(&this->dstAddr, 0, sizeof(this->dstAddr));
		memcpy(&this->dstAddr, dstAddr, addrLen);
		this->dstAddrLen = addrLen;
	}

	set<HtpPacket*, HtpPacketComparator> 		reorganizeBuffer;
	set<uint32_t> 								missingPackets;	
	
	struct sockaddr_storage dstAddr;
	socklen_t dstAddrLen;

private:
	uint32_t sessionID;
	uint32_t currentSendSEQ;
	uint32_t currentRecvSEQ;
	uint32_t recvWindowLeftSeq;
	
};

#endif