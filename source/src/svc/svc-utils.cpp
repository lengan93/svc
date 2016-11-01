#include "svc-utils.h"


//--	UTILS FUNCTION IMPLEMEMTATION	--//
bool isEncryptedCommand(enum SVCCommand command){
	return (command == SVC_CMD_CONNECT_OUTER3);
}

//--	PERIODIC WORKER
PeriodicWorker::PeriodicWorker(int interval, void (*handler)(void*), void* args){
	this->interval = interval;
	this->working = true;
	this->handler = handler;
	this->args = args;
	
	pthread_attr_t threadAttr;
	pthread_attr_init(&threadAttr);
	pthread_create(&this->worker, &threadAttr, handling, this);
	printf("\nperiodic worker started");
}
void PeriodicWorker::stopWorking(){
	//--	disarm automatic
	working = false;
	timer_delete(this->timer);
	//-- can only be interrupted by SIGINT
	pthread_kill(this->worker, SIGINT);
}

void* PeriodicWorker::handling(void* args){
	
	PeriodicWorker* pw = (PeriodicWorker*)args;
	
	struct sigevent evt;
	evt.sigev_notify = SIGEV_SIGNAL;
	evt.sigev_signo = TIMEOUT_SIGNAL;
	evt.sigev_notify_thread_id = pthread_self();
	timer_create(CLOCK_REALTIME, &evt, &pw->timer);

	struct itimerspec time;
	time.it_interval.tv_sec=pw->interval/1000;
	time.it_interval.tv_nsec=(pw->interval - time.it_interval.tv_sec*1000)*1000000;
	time.it_value.tv_sec=pw->interval/1000;
	time.it_value.tv_nsec=(pw->interval - time.it_value.tv_sec*1000)*1000000;
	timer_settime(pw->timer, 0, &time, NULL);		
	
	bool waitrs;
	while (pw->working){
		//--	wait signal then perform handler
		waitrs = waitSignal(SIGALRM);
		if (waitrs){
			//--	perform handler		
			pw->handler(pw->args);
		}
		else{
			//--	SIGINT caught
			printf("\nperiodic worker got SIGINT, stop working");
			pw->stopWorking();
		}
	}
}

void PeriodicWorker::waitStop(){	
	pthread_join(this->worker, NULL);
}

PeriodicWorker::~PeriodicWorker(){
	printf("\nperiodic worker stopped"); fflush(stdout);
}

//--	PACKET HANDLER CLASS	--//
PacketHandler::PacketHandler(int socket){
	//printf("\nnew packet handler created for socket %d", socket); fflush(stdout);
	this->socket = socket;
	this->working = true;
	
	this->readingQueue = new MutexedQueue<SVCPacket*>();
	this->postReadQueue = new MutexedQueue<SVCPacket*>();
	this->preWriteQueue = new MutexedQueue<SVCPacket*>();
	this->writingQueue = new MutexedQueue<SVCPacket*>();
	
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_create(&this->readingThread, &attr, readingLoop, this);
	pthread_create(&this->writingThread, &attr, writingLoop, this);
	pthread_create(&this->processingThread, &attr, processingLoop, this);
}

PacketHandler::~PacketHandler(){
	stopWorking();
}

void PacketHandler::waitStop(){	
	pthread_join(this->readingThread, NULL);
	pthread_join(this->writingThread, NULL);
	pthread_join(this->processingThread, NULL);	
}

void PacketHandler::stopWorking(){
	if (this->working){
		this->working = false;
		//-- writingThread call dequeueWait(-1), which need SIGINT to interrupt
		pthread_kill(this->writingThread, SIGINT);		
		//-- TODO: find a way to safely remove queues without losing data
	}
}

void PacketHandler::setDataHandler(SVCPacketProcessing dataHandler, void* args){
	this->dataHandler = dataHandler;
	this->dataHandlerArgs = args;
}

void PacketHandler::setCommandHandler(SVCPacketProcessing cmdHandler, void* args){
	this->cmdHandler = cmdHandler;
	this->cmdHandlerArgs = args;
}

void PacketHandler::sendPacket(SVCPacket* packet){
	//-- set sending packet bit
	if (this->working){
		packet->packet[INFO_BYTE] |= SVC_SENDING_PACKET;
		this->preWriteQueue->enqueue(packet);
	}
}

void PacketHandler::recvPacket(SVCPacket* packet){
	//-- unset sending packet bit
	if (this->working){
		packet->packet[INFO_BYTE] &= ~SVC_SENDING_PACKET;
		this->readingQueue->enqueue(packet);	
	}
}

SVCPacket* PacketHandler::readPacket(int timeout){
	if (this->working)
		return this->postReadQueue->dequeueWait(timeout);
	else
		return NULL;
}

bool PacketHandler::waitCommand(enum SVCCommand cmd, uint64_t endpointID, SVCPacket* packet, int timeout){
	struct CommandHandler handler;
	handler.waitingThread = pthread_self();
	handler.cmd = cmd;
	handler.endpointID = endpointID;
	handler.packet = packet;
	this->commandHandlerRegistra.push_back(handler);
	
	//-- suspend the calling thread until the correct command is received or the timer expires
	if (timeout>0){
		return waitSignal(QUEUE_DATA_SIGNAL, TIMEOUT_SIGNAL, timeout);
	}
	else{
		return waitSignal(QUEUE_DATA_SIGNAL);
	}
}

void* PacketHandler::readingLoop(void* args){
	PacketHandler* _this = (PacketHandler*)args;
		
	uint8_t* const buffer = (uint8_t*)malloc(SVC_DEFAULT_BUFSIZ);
	ssize_t readrs;
	struct sockaddr_in srcAddr;
	socklen_t srcAddrLen;
	
	while (_this->working){
		//--  !! bringing this following line out of while loop will cause 'stack smashing detected', it has to be initialized before each read to srcAddr
		srcAddrLen = sizeof(srcAddr);
		do{
			readrs = recvfrom(_this->socket, buffer, SVC_DEFAULT_BUFSIZ, MSG_DONTWAIT, (struct sockaddr*)&srcAddr, &srcAddrLen); // in case interrupted by SIGINT, MSG_DONTWAIT helps exit the loop
		}
		while((readrs==-1) && _this->working);
		
		if (readrs>0){			
			SVCPacket* packet = new SVCPacket(buffer, readrs);
			printf("\nread a packet: "); printBuffer(packet->packet, packet->dataLen);
			//-- clear SENDING_PACKET bit
			packet->packet[INFO_BYTE] &= (~SVC_SENDING_PACKET);
			uint8_t infoByte = packet->packet[INFO_BYTE];
			if (((infoByte & SVC_COMMAND_FRAME) != 0) && ((infoByte & SVC_ENCRYPTED) == 0)){
				SVCCommand cmd = (SVCCommand)packet->packet[CMD_BYTE];
				if (cmd == SVC_CMD_CONNECT_OUTER1){
					//-- add source socket address
					packet->pushCommandParam((uint8_t*)&srcAddr, srcAddrLen);
				}
				//else: only CONNECT_OUTER1 need source address for now
			}
			_this->readingQueue->enqueue(packet);
		}
		//else: read received nothing
	}
	
	close(_this->socket);
	delete _this->readingQueue;
	delete buffer;	
}

void* PacketHandler::writingLoop(void* args){
	PacketHandler* _this = (PacketHandler*)args;
	
	SVCPacket* packet;
	int sendrs;
	
	while (_this->working){
		packet = _this->writingQueue->dequeueWait(-1);
		printf("\nwritingLoop, dequeueWait return");
		if (packet!=NULL){
			//-- send this packet to underlayer
			printf("\nsend a packet: "); printBuffer(packet->packet, packet->dataLen);
			sendrs = send(_this->socket, packet->packet, packet->dataLen, 0);
			//-- remove the packet after sending
			delete packet;
			//-- TODO: check this send result for futher decision
		}
		//else: packet = NULL means dequeueWait was interrupted
	}
	
	//-- writing finished
	delete _this->writingQueue;
}

void* PacketHandler::processingLoop(void* args){

	PacketHandler* _this = (PacketHandler*)args;
	
	SVCPacket* packet;
	uint8_t infoByte;
	bool readingTurn = false;
	
	while (_this->working){
		//-- read alternatively
		readingTurn = !readingTurn;
		if (readingTurn){
			packet = _this->readingQueue->dequeue();
		}
		else{
			packet = _this->preWriteQueue->dequeue();
		}
		
		//-- process the packet
		if (packet!=NULL){
			printf("\nprocess a packet: "); printBuffer(packet->packet, packet->dataLen);
			infoByte = packet->packet[INFO_BYTE];
			if ((infoByte & SVC_COMMAND_FRAME) != 0){
				if ((infoByte & SVC_SENDING_PACKET) == 0x00){
					//-- process incoming cmd
					if (_this->cmdHandler!=NULL){
						_this->cmdHandler(packet, _this->cmdHandlerArgs);
					}
					//else: cmdHandler not exists				
				
					//-- !! waitCommand processes after cmdHandler has (possibly) decrypted the packet
					//-- reload infobyte after handling
					infoByte = packet->packet[INFO_BYTE];
					if ((infoByte & SVC_ENCRYPTED) == 0){
						uint64_t endpointID = *((uint64_t*)packet->packet);
						enum SVCCommand cmd = (enum SVCCommand)packet->packet[CMD_BYTE];
						for (int i=0;i<_this->commandHandlerRegistra.size(); i++){
							if ((_this->commandHandlerRegistra[i].cmd == cmd) && (_this->commandHandlerRegistra[i].endpointID == endpointID)){							
								memcpy(_this->commandHandlerRegistra[i].packet->packet, packet->packet, packet->dataLen);
								_this->commandHandlerRegistra[i].packet->dataLen = packet->dataLen;
								pthread_kill(_this->commandHandlerRegistra[i].waitingThread, QUEUE_DATA_SIGNAL);
								//-- remove the handler
								_this->commandHandlerRegistra.erase(_this->commandHandlerRegistra.begin() + i);
								break;
							}
						}
					}
					//else: cmd packet had not been decrypt, can not process
				}
				//else: dont process outgoing command, for now
			}
			else{
				if ((infoByte & SVC_SENDING_PACKET) == 0x00){
					//-- process incoming data
					if (_this->dataHandler!=NULL){
						_this->dataHandler(packet, _this->dataHandlerArgs);
					}
					//else: no data handler, just forward
				}
				//else: dont process outgoing data, for now
			}
			
			//-- !! reload the infoByte after modifications
			infoByte = packet->packet[INFO_BYTE];
			if ((infoByte & SVC_TO_BE_REMOVED) != 0x00){
				printf("\nto be removed");
				delete packet;
			}
			else{			
				//-- forward this packet to corresponding queue
				if (readingTurn){
					printf("\nforward to postread ");
					_this->postReadQueue->enqueue(packet);
				}
				else{
					printf("\nforward to writting ");
					_this->writingQueue->enqueue(packet);
				}
			}
		}
		//else: cannot read packet from queue, reloop
	}
	
	delete _this->postReadQueue;
	delete _this->preWriteQueue;
}



