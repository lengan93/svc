#ifndef	__SVC_UTILS__
#define __SVC_UTILS__

	#include "../utils/MutexedQueue.h"
	#include "svc-header.h"
		
	#include <vector>
	#include <cstring>
	#include <sys/socket.h>

	//--	class pre-declaration
	class SVCPacket;

	//--	return if the command must be encrypted
	bool isEncryptedCommand(enum SVCCommand command);
	
	typedef void (*SVCPacketProcessing)(SVCPacket* packet, void* args);
	
	//-- utils classes
	class SVCPacket{
		public:
			//-- public members
			uint8_t* packet;
			uint32_t dataLen;
			struct sockaddr_storage srcAddr;
			socklen_t srcAddrLen;
			
			//-- constructors/destructors
			
			SVCPacket(){
				packet = (uint8_t*)malloc(SVC_DEFAULT_BUFSIZ);	
				this->dataLen = 0;	
			}
			
			SVCPacket(SVCPacket* packet):SVCPacket(){		
				if (packet!=NULL){
					this->dataLen = packet->dataLen;
					memcpy(this->packet, packet->packet, packet->dataLen);
				}
				else{
					this->dataLen = 0;
				}
			}
			
			SVCPacket(const uint8_t* buffer, uint32_t bufferLen):SVCPacket(){				
				this->dataLen = bufferLen;
				memcpy(this->packet, buffer, this->dataLen);
			}
			
			SVCPacket(uint64_t endpointID):SVCPacket(){
				this->dataLen = SVC_PACKET_HEADER_LEN;
				memset(this->packet, 0, this->dataLen);
				memcpy(this->packet+1, &endpointID, ENDPOINTID_LENGTH);
			}
			
			~SVCPacket(){
				free(this->packet);
			}
			
			bool isCommand(){
				return ((this->packet[INFO_BYTE] & SVC_COMMAND_FRAME) != 0);
			}
			
			void setBody(const uint8_t* body, uint32_t bodyLen){
				memcpy(this->packet + SVC_PACKET_HEADER_LEN, body, bodyLen);
				this->dataLen = SVC_PACKET_HEADER_LEN + bodyLen;
			}
			
			void setSequence(uint64_t sequence){
				memcpy(this->packet+1+ENDPOINTID_LENGTH, &sequence, SEQUENCE_LENGTH);
			}
			
			void setSrcAddr(const struct sockaddr_storage* srcAddr, socklen_t addrLen){
				memset(&this->srcAddr, 0, sizeof(this->srcAddr));
				memcpy(&this->srcAddr, srcAddr, addrLen);
				this->srcAddrLen = addrLen;
			}
			
			void setData(const uint8_t* data, uint32_t dataLen){
				memcpy(this->packet + SVC_PACKET_HEADER_LEN, &dataLen, 4);
				memcpy(this->packet + SVC_PACKET_HEADER_LEN + 4, data, dataLen);
				this->dataLen = SVC_PACKET_HEADER_LEN + 4 + dataLen; //-- 4 byte datalen
				this->packet[INFO_BYTE] &= 0x7F; //-- set 7th bit to 0: data
			}
			
			void extractData(uint8_t* data, uint32_t* dataLen){
				*dataLen = *((uint32_t*)(this->packet+SVC_PACKET_HEADER_LEN));
				//-- TODO: possible error
				memcpy(data, this->packet + SVC_PACKET_HEADER_LEN + 4, this->dataLen - SVC_PACKET_HEADER_LEN - 4);
			}			
			
			//-- public methods
			void setCommand(enum SVCCommand cmd){
				//-- reset length
				this->dataLen = SVC_PACKET_HEADER_LEN + 1;
				//-- set info byte				
				packet[INFO_BYTE] |= SVC_COMMAND_FRAME; //-- set info byte
				packet[INFO_BYTE] |= SVC_URGENT_PRIORITY; 	
				//-- set commandID
				packet[SVC_PACKET_HEADER_LEN] = (uint8_t)cmd;				
			}
			
			void switchCommand(enum SVCCommand cmd){
				this->packet[CMD_BYTE] = (uint8_t)cmd;
			}
			
			void pushCommandParam(const uint8_t* param, uint16_t paramLen){					
				//-- copy new param to packet
				memcpy(this->packet+this->dataLen, param, paramLen);
				memcpy(this->packet+this->dataLen+paramLen, &paramLen, 2);
				this->dataLen += 2 + paramLen;
			}
			
			bool popCommandParam(uint8_t* param, uint16_t* paramLen){
				*paramLen = *((uint16_t*)(this->packet+this->dataLen-2));
				if (*paramLen + SVC_PACKET_HEADER_LEN < this->dataLen){
					memcpy(param, this->packet+this->dataLen-2-*paramLen, *paramLen);
					//-- reduce the packet len
					this->dataLen -= 2 + *paramLen;
					return true;
				}
				else{
					return false;
				}				
			}
	};
	
	class PacketHandler{
	
		class CommandHandler{
			public:
				uint64_t endpointID;
				enum SVCCommand cmd;
				pthread_mutex_t waitingMutex;
				pthread_cond_t waitingCond;
			
				CommandHandler(){
					pthread_mutexattr_t mutexAttr;
					pthread_condattr_t condAttr;
					
					pthread_mutexattr_init(&mutexAttr);
					pthread_mutex_init(&this->waitingMutex, &mutexAttr);				
					pthread_condattr_init(&condAttr);
					pthread_cond_init(&this->waitingCond, &condAttr); 
				}
				
				~CommandHandler(){
				}
		};
		
		private:
			//--	static methods
			static void* processingLoop(void* args);

			MutexedQueue<SVCPacket*>* readingQueue;
			
			//--	members
			volatile bool working;
						
			
			void* packetHandlerArgs;
			SVCPacketProcessing packetHandler;
			vector<CommandHandler*> commandHandlerRegistra;
						
		public:
			pthread_t processingThread;
			//--	constructors/destructors
			PacketHandler(MutexedQueue<SVCPacket*>* readingQueue, SVCPacketProcessing handler, void* args);
			virtual ~PacketHandler();
			
			//--	methods			
			bool waitCommand(enum SVCCommand cmd, uint64_t endpointID, int timeout);
			void notifyCommand(enum SVCCommand cmd, uint64_t endpointID);
			
			void stopWorking();
			int waitStop();
	};
	
#endif
