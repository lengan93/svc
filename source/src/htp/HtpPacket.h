#ifndef __HTP_PACKET_H__
#define __HTP_PACKET_H__

#include "Htp-header.h"

using namespace std::chrono;

class HtpPacket{
	public:
		//-- public members
		uint8_t* packet;
		uint32_t packetLen;
		struct sockaddr_storage srcAddr;
		socklen_t srcAddrLen;
		
		struct sockaddr_storage dstAddr;
		socklen_t dstAddrLen;
		//-- constructors/destructors

		high_resolution_clock::time_point timestamp;
		Timer* timer = nullptr;

		bool acked = false;

		int8_t resend_times = 0;
		
		HtpPacket(uint32_t bufferLen = HTP_DEFAULT_BUFSIZ){
			packet = (uint8_t*)malloc(bufferLen);
			memset(this->packet, 0, bufferLen);
			this->packetLen = bufferLen;
			this->srcAddrLen = sizeof(srcAddr);
			memset(&(this->srcAddr), 0, srcAddrLen);
			this->dstAddrLen = sizeof(dstAddr);
			memset(&(this->dstAddr), 0, dstAddrLen);
		}
		
		// HtpPacket(HtpPacket* packet):HtpPacket(){		
		// 	if (packet!=NULL){
		// 		this->packetLen = packet->packetLen;
		// 		memcpy(this->packet, packet->packet, packet->packetLen);
		// 	}
		// 	else{
		// 		this->packetLen = 0;
		// 	}
		// }
		
		HtpPacket(const uint8_t* buffer, uint32_t bufferLen):HtpPacket(bufferLen){				
			this->packetLen = bufferLen;
			memcpy(this->packet, buffer, this->packetLen);
		}
					
		~HtpPacket(){
			delete [] this->packet;
			delete this->timer;
		}

		//-- operator== ?????
		
		// bool isCommand(){
		// 	return ((this->packet[INFO_BYTE] & SVC_COMMAND_FRAME) != 0);
		// }
		
		void setBody(const void* body, uint32_t bodyLen){
			memcpy(this->packet + HTP_HEADER_LENGTH, body, bodyLen);
			this->packetLen = HTP_HEADER_LENGTH + bodyLen;
		}
		
		void setSessionID(uint32_t sessionID) {
			memcpy(this->packet+1, &sessionID, HTP_SESSIONID_LENGTH);
		}
		
		uint32_t getSessionID() {
			uint32_t rs = -1;
			if(this->checkLength()){
				rs = *((uint32_t*)(packet+1));
			}
			return rs;
		}

		void setSequence(uint32_t sequence){
			memcpy(this->packet+1+HTP_SESSIONID_LENGTH, &sequence, HTP_SEQUENCE_LENGTH);
		}
		
		uint32_t getSequence() {
			uint32_t rs = -1;
			if(this->checkLength()){
				rs = *((uint32_t*)(packet+1+HTP_SESSIONID_LENGTH));
			}
			return rs;
		}

		void setStream(uint16_t stream) {
			memcpy(this->packet+1+HTP_SESSIONID_LENGTH+HTP_SEQUENCE_LENGTH, 
				&stream, HTP_STREAMID_LENGTH);

		}

		uint16_t getStream() {
			uint16_t rs = -1;
			if(this->checkLength()){
				rs = *((uint16_t*)(packet+1+HTP_SESSIONID_LENGTH+HTP_SEQUENCE_LENGTH));
			}
			return rs;
		}

		void setDstAddr(const struct sockaddr_storage* dstAddr, socklen_t addrLen){
			memset(&this->dstAddr, 0, sizeof(this->dstAddr));
			memcpy(&this->dstAddr, dstAddr, addrLen);
			this->dstAddrLen = addrLen;
		}

		void setSrcAddr(const struct sockaddr_storage* srcAddr, socklen_t addrLen){
			memset(&this->srcAddr, 0, sizeof(this->srcAddr));
			memcpy(&this->srcAddr, srcAddr, addrLen);
			this->srcAddrLen = addrLen;
		}
		
		bool checkLength() {
			return (packetLen >= HTP_PACKET_MINLEN);
		}

		bool isData() {
			if(!this->checkLength()) return false;
			return (packet[0] & HTP_DATA) != 0;
		}

		bool isACK() {
			if(!this->checkLength()) return false;
			return (packet[0] & HTP_ACK) != 0;
		}

		bool isNACK() {
			if(!this->checkLength()) return false;
			return (packet[0] & HTP_NACK) != 0;
		}

		bool nolost() {
			if(!this->checkLength()) return false;
			// return (packet[1] & SVC_NOLOST) != 0;
			return true;
		}

		bool isStreamed() {
			return (packet[0] & HTP_STREAMED) != 0;
		}
		// bool isEncrypted() {
		// 	if(!this->checkLength()) return false;
		// 	return (packet[1] & SVC_ENCRYPTED) != 0;
		// }
		
		void setTimestamp() {
			this->timestamp = high_resolution_clock::now();
		}

		bool timeout() {
			return chrono::duration_cast<chrono::milliseconds>(high_resolution_clock::now() - this->timestamp).count() > HTP_SEND_TIMEOUT;
		}
		
		void setTimer(Timer* timer) {
			this->timer = timer;
		}
};

class HtpPacketComparator
{
public:
	bool operator() (HtpPacket* const& l, HtpPacket* const& r) const{
        HtpPacket* p1 = l;
        HtpPacket* p2 = r;
        if(p1==NULL || p2==NULL) return false;
        uint32_t s1 = p1->getSequence();
        uint32_t s2 = p2->getSequence();

        return s1 < s2;
    }
};


class HtpPacketHash {
public:
	uint32_t operator() (HtpPacket* const& p) const {
		return p->getSequence();
	}
};


#endif