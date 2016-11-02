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
	printf("\nnew packet handler created for socket %d", socket); fflush(stdout);
	this->socket = socket;
	this->working = true;
	this->reading = false;
	this->writing = false;
	
	this->readingQueue = new MutexedQueue<SVCPacket*>();
	this->keepingQueue = new MutexedQueue<SVCPacket*>();	
	this->writingQueue = new MutexedQueue<SVCPacket*>();
	
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_create(&this->processingThread, &attr, processingLoop, this);
}

PacketHandler::~PacketHandler(){
	stopWorking();
}

void PacketHandler::waitStop(){	
	pthread_join(this->processingThread, NULL);
	delete this->keepingQueue;
	pthread_join(this->readingThread, NULL);
	delete this->readingQueue;
	pthread_join(this->writingThread, NULL);
	delete this->writingQueue;
}

void PacketHandler::stopWorking(){
	if (this->working){
		this->working = false;	
	}
}

void PacketHandler::startReading(){
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_create(&this->readingThread, &attr, readingLoop, this);
	this->reading = true;
}

void PacketHandler::startWriting(){
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_create(&this->writingThread, &attr, writingLoop, this);
	this->writing = true;
}

void PacketHandler::setPacketHandler(SVCPacketProcessing handler, void* args){
	this->packetHandler = handler;
	this->packetHandlerArgs = args;
}

void PacketHandler::recvPacket(SVCPacket* packet){
	//-- unset sending packet bit
	if (this->working){		
		this->readingQueue->enqueue(packet);	
	}
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
			//-- set SVC_SOCKET_PACKET bit
			packet->packet[INFO_BYTE] |= SVC_SOCKET_PACKET;
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
	delete buffer;	
}

void* PacketHandler::writingLoop(void* args){
	PacketHandler* _this = (PacketHandler*)args;
	
	SVCPacket* packet;
	int sendrs;
	
	while (_this->working){
		packet = _this->writingQueue->dequeue();
		//printf("\nwritingLoop, dequeueWait return");
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
}

void* PacketHandler::processingLoop(void* args){

	PacketHandler* _this = (PacketHandler*)args;
	
	SVCPacket* packet;
	uint8_t infoByte;
	//bool readingTurn = false;
	
	while (_this->working){
		//-- read alternatively
		packet = _this->readingQueue->dequeue();
		
		//-- process the packet
		if (packet!=NULL){
			printf("\nprocess a packet: "); printBuffer(packet->packet, packet->dataLen);
			infoByte = packet->packet[INFO_BYTE];
			if (_this->packetHandler!=NULL){
				_this->packetHandler(packet, _this->packetHandlerArgs);
				//-- reload info byte
				infoByte = packet->packet[INFO_BYTE];
			}
						
			if ((infoByte & SVC_COMMAND_FRAME) != 0){
				if ((infoByte & SVC_SOCKET_PACKET) != 0x00){				
					//-- !! waitCommand processes after cmdHandler has (possibly) decrypted the packet					
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
			
			if (((infoByte & SVC_TOBE_SAVED) != 0x00) && ((infoByte & SVC_TOBE_FORWARDED) != 0x00)){
				printf("\nto be saved and forward");
				_this->keepingQueue->enqueue(new SVCPacket(packet));
				_this->writingQueue->enqueue(packet);
			}
			else{				
				if ((infoByte & SVC_TOBE_SAVED) != 0x00){
					_this->keepingQueue->enqueue(packet);
				}
				else if ((infoByte & SVC_TOBE_FORWARDED) != 0x00){
					_this->writingQueue->enqueue(packet);
				}
				else{
					delete packet;
				}
			}
		}
		//else: cannot read packet from queue, reloop
	}
}



