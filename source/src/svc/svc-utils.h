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
	
	namespace svc_utils{

		class SVCPacket{
			class DataChunk{
					
				public:
					void* chunk;
					uint16_t chunkLen;

					DataChunk(const void* chunk, uint16_t chunkLen){
						this->chunk = malloc(chunkLen);
						if (this->chunk == NULL){
							throw ERR_NO_MEMORY;
						}
						this->chunkLen = chunkLen;
					}
					~DataChunk(){
						free(this->chunk);
					}
			};
			private:
				uint8_t packetHeader[SVC_PACKET_HEADER_LEN];
				std::vector<DataChunk*> packetBody;

				void clearPacketBody(){
					while (!this->packetBody.empty()){
						delete this->packetBody.back();
						this->packetBody.pop_back();
					}
				}

			public:
				~SVCPacket(){
					this->clearPacketBody();
				}

				SVCPacket(){
					memset(this->packetHeader, 0, SVC_PACKET_HEADER_LEN);
					this->packetBody.clear();
				}

				SVCPacket(const void* buffer, uint16_t bufferLen){
					// cout<<"receive buffer: ";
					// utils::printHexBuffer(buffer, bufferLen);
					//-- check packet validity
					// cout<<"checking packet validty:"<<endl;

					if (bufferLen < SVC_PACKET_HEADER_LEN){
						// cout<<"data shorter than header"<<endl;
						throw ERR_DATA_DAMAGED;
					}
					else{
						bool dataCorrect = true;
						uint8_t* buf8 = (uint8_t*)buffer;
						while (bufferLen > SVC_PACKET_HEADER_LEN){
							uint16_t chunkLen;
							memcpy(&chunkLen, buf8 + bufferLen - 2, 2);
							if ((chunkLen + 2) <= (bufferLen - SVC_PACKET_HEADER_LEN)){
								//-- ok, copy this chunk
								DataChunk* chunk = new DataChunk(buf8 + bufferLen - 2 - chunkLen, chunkLen);
								this->packetBody.insert(this->packetBody.begin(), chunk);
								bufferLen -= (2 + chunkLen);
							}
							else{
								dataCorrect = false;
								break;
							}
						}
						dataCorrect = dataCorrect && (bufferLen == SVC_PACKET_HEADER_LEN);
						if (!dataCorrect){
							//-- remove any allocated data chunk
							this->clearPacketBody();
							// cout<<"data damaged??"<<endl;
							throw ERR_DATA_DAMAGED;
						}
						else{
							memcpy(this->packetHeader, buf8, SVC_PACKET_HEADER_LEN);
						}
					}
				}

				void pushDataChunk(const void* buffer, uint16_t bufferLen){
					DataChunk* chunk = new DataChunk(buffer, bufferLen);
					this->packetBody.push_back(chunk);
				}
				
				bool popDataChunk(uint8_t* buffer, uint16_t* bufferLen){
					if (!this->packetBody.empty()){
						DataChunk* chunk = this->packetBody.back();
						memcpy(buffer, chunk->chunk, chunk->chunkLen);
						*bufferLen = chunk->chunkLen;
						return true;
					}
					else{
						return false;
					}
				}

				uint8_t getInfoByte(){
					return this->packetHeader[0];
				}

				void setInfoByte(uint8_t infoByte){
					this->packetHeader[0] = infoByte;
				}

				uint8_t getExtraInfoByte(){
					return this->packetHeader[1];
				}

				void setExtraInfoByte(uint8_t extraInfoByte){
					this->packetHeader[1] = extraInfoByte;
				}

				uint64_t getEndpointID(){
					return *((uint64_t*)(this->packetHeader + INFO_LENGTH));
				}

				void setEndpointID(uint64_t endpointID){
					memcpy(this->packetHeader + INFO_LENGTH, &endpointID, ENDPOINTID_LENGTH);
				}

				uint32_t getSequence(){
					return *((uint32_t*)(this->packetHeader + INFO_LENGTH + ENDPOINTID_LENGTH));
				}

				void setSequence(uint32_t sequence){
					memcpy(this->packetHeader + INFO_LENGTH + ENDPOINTID_LENGTH, &sequence, SEQUENCE_LENGTH);
				}

				void serialize(uint8_t* buffer, uint16_t* bufferLen){
					memcpy(buffer, this->packetHeader, SVC_PACKET_HEADER_LEN);
					uint16_t pointer = SVC_PACKET_HEADER_LEN;
					for (int i=0; i<this->packetBody.size(); i++){
						memcpy(buffer + pointer, this->packetBody[i]->chunk, this->packetBody[i]->chunkLen);
						memcpy(buffer + pointer + this->packetBody[i]->chunkLen, &this->packetBody[i]->chunkLen, 2);
						pointer += 2 + this->packetBody[i]->chunkLen;
					}
					*bufferLen = pointer;
				}

				void setCommand(enum SVCCommand cmd){
					//-- set info byte				
					this->packetHeader[0] |= SVC_COMMAND_FRAME;
					this->packetHeader[0] |= SVC_URGENT_PRIORITY; 	
					//-- set extra info byte
					this->packetHeader[1] = (uint8_t)cmd;				
				}		
				// void setSrcAddr(const struct sockaddr_storage* srcAddr, socklen_t addrLen){
				// 	memset(&this->srcAddr, 0, sizeof(this->srcAddr));
				// 	memcpy(&this->srcAddr, srcAddr, addrLen);
				// 	this->srcAddrLen = addrLen;
				// }
				
				
		};	
		
		typedef void (*SVCPacketProcessing)(SVCPacket* packet, void* args);

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
						try{
							_this->queue->enqueue(new SVCPacket(buffer, dataLen));		
						}
						catch(std::string& e){
							//-- error packet malformed, log this buffer, or IP address, may be?
						}
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
					std::condition_variable waitingCond;
					
					CommandHandler(){
						this->processed = false;
					}
					~CommandHandler(){
					}
			};
			
			private:
				SVCPacketProcessing packetHandler;
				void* packetHandlerArgs;
				MutexedQueue<SVCPacket*>* readingQueue;

				volatile bool working;				
				std::thread processingThread;

				std::mutex commandHandlerRegistraMutex;
				vector<CommandHandler*> commandHandlerRegistra;

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

					//-- mutex to protect commandHandlerRegistra
					this->commandHandlerRegistraMutex.lock();
					this->commandHandlerRegistra.push_back(handler);
					this->commandHandlerRegistraMutex.unlock();

					std::mutex waitingMutex;
					cv_status rs;
					bool boolRs = false;
					std::unique_lock<std::mutex> lock(waitingMutex);
					//-- suspend the calling thread until the correct command is received or the timer expires	
					if (timeout<0){
						//-- spurious awake may occur, check with working and processed
						handler->waitingCond.wait(lock, [this]{return !this->working;});
						boolRs = handler->processed;
					}
					else{
						rs = handler->waitingCond.wait_for(lock, std::chrono::milliseconds(timeout));
						boolRs = (rs == cv_status::no_timeout);
					}
					waitingMutex.unlock();
					delete handler;
					return boolRs;
				}

				void notifyCommand(enum SVCCommand cmd, uint64_t endpointID){
					this->commandHandlerRegistraMutex.lock();
					for (int i=0;i<this->commandHandlerRegistra.size(); i++){
						CommandHandler* handler = this->commandHandlerRegistra[i];
						if ((handler->cmd == cmd) && (handler->endpointID == endpointID)){
							handler->processed = true;
							handler->waitingCond.notify_all();
							//-- remove the handler
							this->commandHandlerRegistra.erase(this->commandHandlerRegistra.begin() + i);
							break;
						}
					}
					this->commandHandlerRegistraMutex.unlock();
				}

				void stopWorking(){
					this->working = false;
					this->processingThread.join();
				}
		};
	}
#endif
