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
				uint32_t rs;
				rs = *((uint32_t*)(packet+1));
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
			
			bool isData() {
				return (packet[0] == HTP_DATA);
			}

			bool isACK() {
				return (packet[0] == HTP_ACK);
			}

			bool isNACK() {
				return (packet[0] == HTP_NACK);
			}
			// void setData(const uint8_t* data, uint32_t packetLen){
			// 	memcpy(this->packet + HTP_HEADER_LENGTH, &packetLen, 4);
			// 	memcpy(this->packet + HTP_HEADER_LENGTH + 4, data, packetLen);
			// 	this->packetLen = HTP_HEADER_LENGTH + 4 + packetLen; //-- 4 byte packetlen
			// 	this->packet[INFO_BYTE] &= 0x7F; //-- set 7th bit to 0: data
			// }
			
			// void extractData(uint8_t* data, uint32_t* packetLen){
			// 	*packetLen = *((uint32_t*)(this->packet+HTP_HEADER_LENGTH));
			// 	//-- TODO: possible error
			// 	memcpy(data, this->packet + HTP_HEADER_LENGTH + 4, this->packetLen - HTP_HEADER_LENGTH - 4);
			// }			
			
			//-- public methods
			// void setCommand(enum SVCCommand cmd){
			// 	//-- reset length
			// 	this->packetLen = HTP_HEADER_LENGTH + 1;
			// 	//-- set info byte				
			// 	packet[INFO_BYTE] |= SVC_COMMAND_FRAME; //-- set info byte
			// 	packet[INFO_BYTE] |= SVC_URGENT_PRIORITY; 	
			// 	//-- set commandID
			// 	packet[HTP_HEADER_LENGTH] = (uint8_t)cmd;				
			// }
			
			// void switchCommand(enum SVCCommand cmd){
			// 	this->packet[CMD_BYTE] = (uint8_t)cmd;
			// }
			
			// void pushCommandParam(const uint8_t* param, uint16_t paramLen){					
			// 	//-- copy new param to packet
			// 	memcpy(this->packet+this->packetLen, param, paramLen);
			// 	memcpy(this->packet+this->packetLen+paramLen, &paramLen, 2);
			// 	this->packetLen += 2 + paramLen;
			// }
			
			// bool popCommandParam(uint8_t* param, uint16_t* paramLen){
			// 	*paramLen = *((uint16_t*)(this->packet+this->packetLen-2));
			// 	if (*paramLen + HTP_HEADER_LENGTH < this->packetLen){
			// 		memcpy(param, this->packet+this->packetLen-2-*paramLen, *paramLen);
			// 		//-- reduce the packet len
			// 		this->packetLen -= 2 + *paramLen;
			// 		return true;
			// 	}
			// 	else{
			// 		return false;
			// 	}				
			// }
	};

#endif