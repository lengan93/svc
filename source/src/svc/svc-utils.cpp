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
	
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	this->worker = -1;
	if (pthread_create(&this->worker, &attr, handling, this) !=0){
		throw SVC_ERROR_CRITICAL;
	}
}
void PeriodicWorker::stopWorking(){
	//--	disarm automatic
	if (this->working){
		this->working = false;
	}
}

void* PeriodicWorker::handling(void* args){
	
	PeriodicWorker* _this = (PeriodicWorker*)args;
	
	while (_this->working){
		//--	wait signal then perform handler
		if (waitSignal(SIGINT, SIGALRM, _this->interval)){
			//--	SIGINT caught
			_this->stopWorking();			
		}
		else{
			//--	perform handler		
			_this->handler(_this->args);
		}
	}
}

void PeriodicWorker::waitStop(){	
	if (this->worker != -1) pthread_join(this->worker, NULL);
}

PeriodicWorker::~PeriodicWorker(){
	//printf("\nperiodic worker stopped"); fflush(stdout);
}

//--	PACKET HANDLER CLASS	--//
PacketHandler::PacketHandler(MutexedQueue<SVCPacket*>* readingQueue, SVCPacketProcessing handler, void* args){
	this->packetHandler = handler;
	this->packetHandlerArgs = args;
	this->readingQueue = readingQueue;

	this->working = true;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	this->processingThread = -1;
	if (pthread_create(&this->processingThread, &attr, processingLoop, this) !=0){
		throw SVC_ERROR_CRITICAL;
	}
}

PacketHandler::~PacketHandler(){
	stopWorking();
	//printf("\npacket handler destructed"); fflush(stdout);
}

void PacketHandler::waitStop(){	
	if (this->processingThread!=-1){
		pthread_join(this->processingThread, NULL);
	}
}

void PacketHandler::stopWorking(){	
	if (this->working){		
		this->working = false;		
	}
}

bool PacketHandler::waitCommand(enum SVCCommand cmd, uint64_t endpointID, int timeout){
	struct CommandHandler handler;	
	handler.waitingThread = pthread_self();
	handler.cmd = cmd;
	handler.endpointID = endpointID;
	this->commandHandlerRegistra.push_back(handler);
	
	//-- suspend the calling thread until the correct command is received or the timer expires
	if (timeout>0){
		return waitSignal(QUEUE_DATA_SIGNAL, TIMEOUT_SIGNAL, timeout);
	}
	else{
		return waitSignal(QUEUE_DATA_SIGNAL);
	}
}

void* PacketHandler::processingLoop(void* args){

	PacketHandler* _this = (PacketHandler*)args;
	
	SVCPacket* packet = NULL;
	uint8_t infoByte;
	
	while (_this->working){
		//printf("\npacket handler %d dequeuewait -1 of %d", (void*)_this, (void*)_this->readingQueue);
		packet = _this->readingQueue->dequeueWait(1000);		
		//printf("\ndequeueWait 1000 return with packet");
		//-- process the packet
		if (packet!=NULL){			
			printf("\npacket handler %d process a packet: ", (void*)_this); printBuffer(packet->packet, packet->dataLen);
			infoByte = packet->packet[INFO_BYTE];
			if (_this->packetHandler!=NULL){
				_this->packetHandler(packet, _this->packetHandlerArgs);
				//-- reload info byte
				//infoByte = packet->packet[INFO_BYTE];
			}
						
			if ((infoByte & SVC_COMMAND_FRAME) != 0){
				//if ((infoByte & SVC_INCOMING_PACKET) != 0x00){				
					//-- !! waitCommand processes after cmdHandler has (possibly) decrypted the packet					
					if ((infoByte & SVC_ENCRYPTED) == 0){
						uint64_t endpointID = *((uint64_t*)packet->packet);
						enum SVCCommand cmd = (enum SVCCommand)packet->packet[CMD_BYTE];
						for (int i=0;i<_this->commandHandlerRegistra.size(); i++){
							if ((_this->commandHandlerRegistra[i].cmd == cmd) && (_this->commandHandlerRegistra[i].endpointID == endpointID)){								
								pthread_kill(_this->commandHandlerRegistra[i].waitingThread, QUEUE_DATA_SIGNAL);
								//-- remove the handler
								_this->commandHandlerRegistra.erase(_this->commandHandlerRegistra.begin() + i);
								break;
							}
						}
					}
					//else: cmd packet had not been decrypt, can not process
				//}
				//else: dont process outgoing command, for now
			}
			
			if ((infoByte & SVC_TOBE_REMOVED) != 0x00){
				delete packet;
			}
		}
		//else{//--TODO: can count dequeue fails to predict the network status}
	}	
}



