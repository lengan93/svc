#ifndef	__SVC_UTILS__
#define __SVC_UTILS__

	#include "../utils/MutexedQueue.h"
	#include "../utils/NamedPipe.h"
	#include "svc-header.h"
	
	#include <chrono>
	#include <mutex>
	#include <thread>
	#include <condition_variable>
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
						memcpy(this->chunk, chunk, chunkLen);
						this->chunkLen = chunkLen;
					}
					~DataChunk(){
						free(this->chunk);
					}
			};
			private:
				void clearPacketBody(){
					while (!this->packetBody.empty()){
						delete this->packetBody.back();
						this->packetBody.pop_back();
					}
				}

			public:
				DataEndpointAddr* senderAddr;
				uint8_t packetHeader[SVC_PACKET_HEADER_LEN];
				std::vector<DataChunk*> packetBody;

				~SVCPacket(){
					this->clearPacketBody();
				}

				SVCPacket(){
					memset(this->packetHeader, 0, SVC_PACKET_HEADER_LEN);
					this->packetBody.clear();
				}

				SVCPacket(const SVCPacket* packet){
					memcpy(this->packetHeader, packet->packetHeader, SVC_PACKET_HEADER_LEN);
					for (int i=0; i<packet->packetBody.size(); i++){
						this->packetBody.push_back(new DataChunk(packet->packetBody[i]->chunk, packet->packetBody[i]->chunkLen));
					}
				}

				SVCPacket(const void* buffer, uint16_t bufferLen){
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
							throw ERR_DATA_DAMAGED;
						}
						else{
							memcpy(this->packetHeader, buf8, SVC_PACKET_HEADER_LEN);
						}
					}
				}

				DataChunk* operator[](int index){
					if (index < this->packetBody.size()){
						return this->packetBody[this->packetBody.size() - 1 -index];
					}
					else{
						return NULL;
					}
				}

				void pushDataChunk(const void* buffer, uint16_t bufferLen){
					DataChunk* chunk = new DataChunk(buffer, bufferLen);
					this->packetBody.push_back(chunk);
				}
				
				bool popDataChunk(void* buffer = NULL, uint16_t* bufferLen = NULL){
					if (!this->packetBody.empty()){
						DataChunk* chunk = this->packetBody.back();
						if (buffer != NULL){
							memcpy(buffer, chunk->chunk, chunk->chunkLen);
						}
						if (bufferLen != NULL){
							*bufferLen = chunk->chunkLen;
						}
						this->packetBody.pop_back();
						delete chunk;
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
		};	
		
		typedef void (*SVCPacketProcessing)(SVCPacket* packet, void* args);

		class SVCPacketReader{
			private:
				DataEndpoint* dataEndpoint;
				MutexedQueue<SVCPacket*>* queue;
				uint8_t option;

				std::thread readingThread;
				volatile bool working;

				static void reading_loop(void* args){
					uint8_t buffer[SVC_DEFAULT_BUFSIZ];
					SVCPacketReader* _this = (SVCPacketReader*) args;
					while (_this && _this->working){
						ssize_t dataLen = _this->dataEndpoint->read(buffer, SVC_DEFAULT_BUFSIZ, 0);
						if (dataLen > 0){
							try{
								if (_this->queue && _this->queue->isOpen()){
									_this->queue->enqueue(new SVCPacket(buffer, dataLen));
									// cout<<"get packet:";
									// printHexBuffer(buffer, dataLen);
								}
								else{
									//-- queue closed, ignore data
								}
							}
							catch(std::string& e){
								//-- error packet malformed, log this buffer, or IP address, may be?
							}
						}
					}
				}

				static void reading_loop_addr(void* args){
					uint8_t buffer[SVC_DEFAULT_BUFSIZ];
					SVCPacketReader* _this = (SVCPacketReader*) args;
					while (_this && _this->working){
						DataEndpointAddr* senderAddr;
						ssize_t dataLen = _this->dataEndpoint->readFrom(&senderAddr, buffer, SVC_DEFAULT_BUFSIZ, 0);
						if (dataLen > 0){
							try{
								if (_this->queue && _this->queue->isOpen()){
									SVCPacket* packet = new SVCPacket(buffer, dataLen);
									packet->senderAddr = senderAddr;
									_this->queue->enqueue(packet);
									// cout<<"get packet:";
									// printHexBuffer(buffer, dataLen);
								}
								else{
									delete senderAddr;
									//-- queue closed, ignore data
								}
							}
							catch(std::string& e){
								delete senderAddr;
								//-- error packet malformed, log this buffer, or IP address, may be?
							}
						}
					}
				}

			public:
				static const uint8_t WITH_SENDER_ADDR = 0x01;

				SVCPacketReader(DataEndpoint* dataEndpoint, MutexedQueue<SVCPacket*>* queue, uint8_t option){
					this->option = option;
					this->dataEndpoint = dataEndpoint;
					this->queue = queue;
					this->working = true;
					if ((option & WITH_SENDER_ADDR) != 0x00){
						this->readingThread = thread(reading_loop_addr, this);
					}
					else{
						this->readingThread = thread(reading_loop, this);
					}
					this->readingThread.detach();
				}
				void stopWorking(){
					this->working = false;
				}
				~SVCPacketReader(){			
					stopWorking();
				}
		};

		class SVCPacketHandler{	
			private:
				class CommandHandler{
					public:
						enum SVCCommand cmd;
						uint64_t endpointID;
						bool processed;
						uint8_t* data;
						std::condition_variable waitingCond;
						
						CommandHandler(){
							this->processed = false;
							this->data = NULL;
						}
						~CommandHandler(){
						}
				};
				
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
					
					while (_this && _this->working){
						packet = _this->readingQueue->dequeueWait(-1);
						//-- process the packet
						if (packet != NULL){						
							if (_this->packetHandler != NULL){
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
					this->processingThread.detach();
				}
				~SVCPacketHandler(){
					stopWorking();
				}
				
				//--	waitCommand
				//--	To simplify the signature, the calling method of this function must know exactly the size of returned data
				//--	If a structure is expected, should he cast it in a structure pointer
				bool waitCommand(enum SVCCommand cmd, uint64_t endpointID, int timeout, uint8_t** data){
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
						handler->waitingCond.wait(lock, [this, handler]{return !this->working || handler->processed;});
						boolRs = handler->processed;
					}
					else{
						rs = handler->waitingCond.wait_for(lock, std::chrono::milliseconds(timeout));
						boolRs = (rs == cv_status::no_timeout);
					}
					if (data != NULL){
						*data = handler->data;
					}
					waitingMutex.unlock();
					delete handler;
					return boolRs;
				}

				void notifyCommand(enum SVCCommand cmd, uint64_t endpointID, uint8_t* data = NULL, ssize_t dataLen = 0){
					this->commandHandlerRegistraMutex.lock();
					for (int i=0;i<this->commandHandlerRegistra.size(); i++){
						CommandHandler* handler = this->commandHandlerRegistra[i];
						if ((handler->cmd == cmd) && (handler->endpointID == endpointID)){
							handler->processed = true;
							if ((dataLen > 0) && (data != NULL)){
								handler->data = (uint8_t*)malloc(dataLen);
								memcpy(handler->data, data, dataLen);
							}
							handler->waitingCond.notify_all();
							//-- remove the handler
							this->commandHandlerRegistra.erase(this->commandHandlerRegistra.begin() + i);
						}
					}
					this->commandHandlerRegistraMutex.unlock();
				}

				void stopWorking(){
					if (this->working){
						this->working = false;
						//-- notify all remain blocked waitCommand
						this->commandHandlerRegistraMutex.lock();
						for (int i=0;i<this->commandHandlerRegistra.size(); i++){
							CommandHandler* handler = this->commandHandlerRegistra[i];
							handler->waitingCond.notify_all();
							this->commandHandlerRegistra.erase(this->commandHandlerRegistra.begin() + i);
						}
						this->commandHandlerRegistraMutex.unlock();
					}
				}
		};
	}
#endif
