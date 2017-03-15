#ifndef	__SVC_UTILS__
#define __SVC_UTILS__

	#include "../utils/MutexedQueue.h"
	#include "../utils/NamedPipe.h"
	#include "svc-header.h"
	
	#include <chrono>
	#include <mutex>
	#include <condition_variable>
	#include <thread>
	#include <vector>
	#include <cstring>
	#include <sys/socket.h>
	
	namespace svc_utils{

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
		
		typedef void (*SVCPacketProcessing)(SVCPacket* packet, void* args);
		
		//-- utils classes

		class SVCPacketReader{
			NamedPipe* pipe;
			MutexedQueue<SVCPacket*>* queue;

			std::thread readingThread;
			volatile bool working;

			static void reading_loop(void* args){
				uint8_t buffer[SVC_DEFAULT_BUFSIZ];
				SVCPacketReader* _this = (SVCPacketReader*) args;
				while (_this->working){
					ssize_t dataLen = _this->pipe->read(buffer, SVC_DEFAULT_BUFSIZ);
					if (dataLen > 0){
						_this->queue->enqueue(new SVCPacket(buffer, dataLen));
					}
				}
			}

			public:
				SVCPacketReader(NamedPipe* pipe, MutexedQueue<SVCPacket*>* queue){
					this->pipe = pipe;
					this->queue = queue;
					this->working = true;
					this->readingThread = thread(reading_loop, this);
				}
				void stopWorking(){
					this->working = false;
					this->readingThread.join();
				}
				~SVCPacketReader(){
					if (this->working){
						stopWorking();
					}
				}
		};

	
		class SVCPacketHandler{
		
			class CommandHandler{
				public:
					enum SVCCommand cmd;
					uint64_t endpointID;
					bool processed;
					std::mutex waitingMutex;
					std::condition_variable waitingCond;
					CommandHandler(){
						this->processed = false;
					}
					~CommandHandler(){
					}
			};
			
			private:
				SVCPacketProcessing packetHandler;
				MutexedQueue<SVCPacket*>* readingQueue;
				volatile bool working;								
				void* packetHandlerArgs;
				std::thread processingThread;

				//--	static methods
				static void processingLoop(void* args){
					SVCPacketHandler* _this = (SVCPacketHandler*)args;
					SVCPacket* packet = NULL;
					uint8_t infoByte;
					
					while (_this->working || _this->readingQueue->notEmpty()){	
						packet = _this->readingQueue->dequeueWait(-1);
						//-- process the packet
						if (packet!=NULL){						
							if (_this->packetHandler!=NULL){
								_this->packetHandler(packet, _this->packetHandlerArgs);
							}						
						}
					}
				}
				vector<CommandHandler*> commandHandlerRegistra;

			public:
				SVCPacketHandler(MutexedQueue<SVCPacket*>* queue, SVCPacketProcessing handler, void* args){
					this->packetHandler = handler;
					this->packetHandlerArgs = args;
					this->readingQueue = queue;
					this->working = true;
					this->processingThread = thread(processingLoop, this);
				}
				virtual ~SVCPacketHandler(){
					if (this->working){
						stopWorking();
					}
				}
				
				//--	methods			
				bool waitCommand(enum SVCCommand cmd, uint64_t endpointID, int timeout){
					CommandHandler* handler = new CommandHandler();		
					handler->cmd = cmd;
					handler->endpointID = endpointID;
					handler->processed = false;
					this->commandHandlerRegistra.push_back(handler);
					
					cv_status rs;
					bool boolRs = false;
					std::unique_lock<std::mutex> lock(handler->waitingMutex);
					//-- suspend the calling thread until the correct command is received or the timer expires	
					if (timeout<0){
						//-- spurious awake may occur
						handler->waitingCond.wait(lock);
						boolRs = handler->processed;
					}
					else{						
						rs = handler->waitingCond.wait_for(lock, std::chrono::milliseconds(timeout));
						boolRs = (rs == cv_status::no_timeout);
					}
					handler->waitingMutex.unlock();
					delete handler;
					return boolRs;
				}
				void notifyCommand(enum SVCCommand cmd, uint64_t endpointID){
					for (int i=0;i<this->commandHandlerRegistra.size(); i++){
						CommandHandler* handler = this->commandHandlerRegistra[i];
						if ((handler->cmd == cmd) && (handler->endpointID == endpointID)){														
							handler->waitingMutex.lock();
							handler->processed = true;
							handler->waitingCond.notify_all();
							handler->waitingMutex.unlock();
							//-- remove the handler
							this->commandHandlerRegistra.erase(this->commandHandlerRegistra.begin() + i);
							break;
						}
					}
				}
				void stopWorking(){
					this->working = false;
					this->processingThread.join();
				}
		};
	}
#endif
