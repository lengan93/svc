#ifndef __HTP_PACKET_H__
#define __HTP_PACKET_H__

#include "Htp-header.h"

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
		
		HtpPacket(){
			packet = (uint8_t*)malloc(HTP_DEFAULT_BUFSIZ);	
			this->packetLen = 0;	
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
		
		HtpPacket(const uint8_t* buffer, uint32_t bufferLen):HtpPacket(){				
			this->packetLen = bufferLen;
			memcpy(this->packet, buffer, this->packetLen);
		}
					
		~HtpPacket(){
			free(this->packet);
		}
		
		// bool isCommand(){
		// 	return ((this->packet[INFO_BYTE] & SVC_COMMAND_FRAME) != 0);
		// }
		
		void setBody(const uint8_t* body, uint32_t bodyLen){
			memcpy(this->packet + HTP_HEADER_LENGTH, body, bodyLen);
			this->packetLen = HTP_HEADER_LENGTH + bodyLen;
		}
		
		void setSequence(uint32_t sequence){
			memcpy(this->packet+1, &sequence, HTP_SEQUENCE_LENGTH);
		}
		
		uint32_t getSequence() {
			uint32_t rs = -1;
			if(this->checkLength()){
				rs = *((uint32_t*)(packet+1));
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

		// bool isEncrypted() {
		// 	if(!this->checkLength()) return false;
		// 	return (packet[1] & SVC_ENCRYPTED) != 0;
		// }
		
		
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

#endif