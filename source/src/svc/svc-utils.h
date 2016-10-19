#ifndef	__SVC_UTILS__
#define __SVC_UTILS__

	#include "../utils/SharedMutex.h"
	#include "../utils/Message.h"
	#include "../utils/utils-functions.h"
	#include "svc-header.h"
	
	#include <cstring>
	#include <vector>
	#include <sys/socket.h>

	//--	class pre-declaration
	class SVCPacket;

	//--	return if the command must be encrypted
	bool isEncryptedCommand(enum SVCCommand command);
	
	typedef void (*SVCPacketProcessing)(SVCPacket* packet, void* args);
	
	//-- utils classes
	class SVCPacket{
		public:
			uint8_t* packet;
			uint32_t dataLen;
			
			//-- constructors/destructors
			
			SVCPacket(){
				this->packet = (uint8_t*)malloc(SVC_DEFAULT_BUFSIZ);
				this->dataLen = 0;
			}
			
			SVCPacket(const uint8_t* buffer, uint32_t bufferLen){
				this->packet = (uint8_t*)malloc(SVC_DEFAULT_BUFSIZ);
				this->dataLen = bufferLen;
				memcpy(this->packet, buffer, bufferLen);
			}
			
			SVCPacket(uint64_t endpointID){
				this->packet = (uint8_t*)malloc(SVC_DEFAULT_BUFSIZ);			
				this->dataLen = SVC_PACKET_HEADER_LEN;
				memset(this->packet, 0, this->dataLen);
				memcpy(this->packet, (uint8_t*)&endpointID, ENDPOINTID_LENGTH);
			}
			
			~SVCPacket(){
				delete this->packet;
			}
			
			bool isCommand(){
				return ((this->packet[ENDPOINTID_LENGTH] & SVC_COMMAND_FRAME) != 0);
			}
			
			//-- public methods
			void setCommand(enum SVCCommand cmd){
				//-- reset length
				this->dataLen = SVC_PACKET_HEADER_LEN + 2;
				//-- set info byte
				packet[ENDPOINTID_LENGTH] |= 0x80;
				packet[ENDPOINTID_LENGTH] |= SVC_COMMAND_FRAME; //-- set info byte
				packet[ENDPOINTID_LENGTH] |= SVC_URGENT_PRIORITY; 	
				//-- set commandID
				packet[SVC_PACKET_HEADER_LEN] = (uint8_t)cmd;
				//-- reset number of param
				packet[SVC_PACKET_HEADER_LEN + 1] = 0x00;	
			}
			void switchCommandID(enum SVCCommand cmd){
				this->packet[SVC_PACKET_HEADER_LEN] = (uint8_t)cmd;
			}
			void pushCommandParam(const uint8_t* param, uint16_t paramLen){					
				//-- copy new param to packet
				memcpy(this->packet+this->dataLen, (uint8_t*)&paramLen, 2);
				memcpy(this->packet+this->dataLen+2, param, paramLen);				
				//-- add 1 to number of param
				this->packet[SVC_PACKET_HEADER_LEN + 1] += 1;
				this->dataLen += 2 + paramLen;
				//printf("\nadd param: "); printBuffer(param, paramLen); fflush(stdout);		
			}
			void popCommandParam(uint8_t* param, uint16_t* paramLen){
				uint8_t argc = this->packet[SVC_PACKET_HEADER_LEN + 1];
				if (argc>0){
					argc -= 1;
					uint8_t* p = this->packet + SVC_PACKET_HEADER_LEN + 1;
					for (int i=0; i<argc; i++){
						p += 2 + *((uint16_t*)p);
					}
					*paramLen = *((uint16_t*)p);
					memcpy(param, p, *paramLen);
				}
				else{
					paramLen = 0;
					param = this->packet + SVC_PACKET_HEADER_LEN + 2;
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
				SVCPacket* packet;
		};
		
		private:
			//--	static methods
			static void* readingLoop(void* args);
			
			//--	members
			vector<CommandHandler> commandHandlerRegistra;
			int socket;
			bool working;
			pthread_t readingThread;
			SVCPacketProcessing cmdHandler;
			void* cmdHandlerArgs;
			SVCPacketProcessing dataHandler;
			void* dataHandlerArgs;

		public:
			//--	constructors/destructors
			PacketHandler(int socket);
			virtual ~PacketHandler();
			
			//--	methods
			void setCommandHandler(SVCPacketProcessing cmdHandler, void* args);
			void setDataHandler(SVCPacketProcessing dataHandler, void* args);
			bool waitCommand(enum SVCCommand cmd, uint64_t endpointID, SVCPacket* packet, int timeout);
			int sendPacket(SVCPacket* packet);
			void stopWorking();
			void waitStop();
	};
	
#endif