#ifndef	__SVC_UTILS__
#define __SVC_UTILS__

	#include "../utils/MutexedQueue.h"
	#include "../utils/Message.h"
	#include "svc-header.h"
	
	#include <cstring>
	#include <vector>
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <unistd.h>

	//--	class pre-declaration
	class SVCPacket;

	//--	return if the command must be encrypted
	bool isEncryptedCommand(enum SVCCommand command);
	
	typedef void (*SVCPacketProcessing)(SVCPacket* packet, void* args);
	
	//-- utils classes
	class SVCPacket{
		public:
			//-- public members
			uint8_t* packet; //[SVC_DEFAULT_BUFSIZ];
			uint32_t dataLen;
			
			//-- constructors/destructors
			
			SVCPacket(){
				printf("\npacket create: 0x%08X", (void*)this); fflush(stdout);
				this->dataLen = 0;
				this->packet = (uint8_t*)malloc(SVC_DEFAULT_BUFSIZ);
			}
			
			SVCPacket(SVCPacket* packet):SVCPacket(){		
				if (packet!=NULL){
					this->dataLen = packet->dataLen;
					memcpy(this->packet, packet->packet, this->dataLen);
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
				memcpy(this->packet, &endpointID, ENDPOINTID_LENGTH);
			}
			
			~SVCPacket(){
				printf("\npacket destroyed: 0x%08X", (void*)this); fflush(stdout);
				free(this->packet);
			}
			
			bool isCommand(){
				return ((this->packet[INFO_BYTE] & SVC_COMMAND_FRAME) != 0);
			}
			
			void setData(const uint8_t* data, uint32_t dataLen){
				memcpy(this->packet + SVC_PACKET_HEADER_LEN, &dataLen, 4);
				memcpy(this->packet + SVC_PACKET_HEADER_LEN + 4, data, dataLen);				
				this->dataLen = SVC_PACKET_HEADER_LEN + 4 + dataLen; //-- 4 byte datalen
				this->packet[INFO_BYTE] &= 0x7F; //-- set 7th bit to 0: data
			}
			
			//-- public methods
			void setCommand(enum SVCCommand cmd){
				//-- reset length
				this->dataLen = SVC_PACKET_HEADER_LEN + 2;
				//-- set info byte				
				packet[INFO_BYTE] |= SVC_COMMAND_FRAME; //-- set info byte
				packet[INFO_BYTE] |= SVC_URGENT_PRIORITY; 	
				//-- set commandID
				packet[SVC_PACKET_HEADER_LEN] = (uint8_t)cmd;
				//-- reset number of param
				packet[SVC_PACKET_HEADER_LEN + 1] = 0x00;	
			}
			
			void switchCommand(enum SVCCommand cmd){
				this->packet[CMD_BYTE] = (uint8_t)cmd;
			}
			
			void pushCommandParam(const uint8_t* param, uint16_t paramLen){					
				//-- copy new param to packet
				memcpy(this->packet+this->dataLen, &paramLen, 2);
				memcpy(this->packet+this->dataLen+2, param, paramLen);				
				//-- add 1 to number of param
				this->packet[SVC_PACKET_HEADER_LEN + 1] += 1;
				this->dataLen += 2 + paramLen;
			}
			
			void popCommandParam(uint8_t* param, uint16_t* paramLen){
				uint8_t argc = this->packet[SVC_PACKET_HEADER_LEN + 1];
				if (argc>0){						
					uint8_t* p = this->packet + SVC_PACKET_HEADER_LEN + 2;
					for (int i=0; i<argc-1; i++){
						p += 2 + *((uint16_t*)p);
					}
					*paramLen = *((uint16_t*)p);
					memcpy(param, p+2, *paramLen);
					//-- reduce the packet len
					this->packet[SVC_PACKET_HEADER_LEN + 1] -= 1;
					this->dataLen -= 2 + *paramLen;
				}
				else{
					*paramLen = 0;					
				}				
			}
	};
	
	class PeriodicWorker{
		private:
			timer_t timer;
			pthread_t worker;
			volatile bool working;
			void (*handler)(void*);
			void* args;
			int interval;
			
			static void* handling(void* args);
			
		public:
			PeriodicWorker(int interval, void (*handler)(void* args), void* args);
			~PeriodicWorker();			
			void stopWorking();
			void waitStop();
	};
	
	class PacketHandler{
	
		class CommandHandler{
			public:
				uint64_t endpointID;
				enum SVCCommand cmd;
				pthread_t waitingThread;			
		};
		
		private:
			//--	static methods
			//static void* readingLoop(void* args);
			//static void* writingLoop(void* args);
			static void* processingLoop(void* args);

			MutexedQueue<SVCPacket*>* readingQueue;
			//MutexedQueue<SVCPacket*>* keepingQueue;
			//MutexedQueue<SVCPacket*>* writingQueue;
			
			//--	members
			//int socket;
			volatile bool working;
			//volatile bool reading;
			//volatile bool writing;
			
			//pthread_t readingThread;
			//pthread_t writingThread;
			pthread_t processingThread;			
			
			void* packetHandlerArgs;
			SVCPacketProcessing packetHandler;
			vector<CommandHandler> commandHandlerRegistra;
						
		public:
			//--	constructors/destructors
			PacketHandler(MutexedQueue<SVCPacket*>* readingQueue, SVCPacketProcessing handler, void* args);
			virtual ~PacketHandler();
			
			//--	methods			
			bool waitCommand(enum SVCCommand cmd, uint64_t endpointID, int timeout);
			void notifyCommand(enum SVCCommand cmd, uint64_t endpointID);
			
			void stopWorking();
			void waitStop();
	};
	
#endif
