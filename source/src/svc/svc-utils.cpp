#include "svc-utils.h"


//--	UTILS FUNCTION IMPLEMEMTATION	--//
bool isEncryptedCommand(enum SVCCommand command){
	return (command == SVC_CMD_CONNECT_OUTER3);
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
}

int PacketHandler::waitStop(){	
	if (this->processingThread!=-1){
		return pthread_join(this->processingThread, NULL);
	}
}

void PacketHandler::stopWorking(){	
	if (this->working){
		this->working = false;		
	}
}

bool PacketHandler::waitCommand(enum SVCCommand cmd, uint64_t endpointID, int timeout){
	CommandHandler* handler = new CommandHandler();		
	handler->cmd = cmd;
	handler->endpointID = endpointID;
	this->commandHandlerRegistra.push_back(handler);
	
	int rs;
	pthread_mutex_lock(&handler->waitingMutex);
	//-- suspend the calling thread until the correct command is received or the timer expires	
	if (timeout<0){
		rs = pthread_cond_wait(&handler->waitingCond, &handler->waitingMutex);		
	}
	else{						
		struct timespec timeoutSpec;
		clock_gettime(CLOCK_REALTIME, &timeoutSpec);
		//-- add timeout to timeoutSpec
		uint32_t addedSec = timeout/1000;
		uint32_t addedNsec = (timeout%1000)*1000000;
		if (addedNsec + timeoutSpec.tv_nsec >= 1000000000){
			timeoutSpec.tv_nsec = addedNsec + timeoutSpec.tv_nsec - 1000000000;
			addedSec +=1;
		}
		else{
			timeoutSpec.tv_nsec = addedNsec + timeoutSpec.tv_nsec;
		}
		timeoutSpec.tv_sec += addedSec;
		rs = pthread_cond_timedwait(&handler->waitingCond, &handler->waitingMutex, &timeoutSpec);
	}
	pthread_mutex_unlock(&handler->waitingMutex);
	delete handler;
	
	return rs==0;
}

void PacketHandler::notifyCommand(enum SVCCommand cmd, uint64_t endpointID){

	for (int i=0;i<this->commandHandlerRegistra.size(); i++){
		CommandHandler* handler = this->commandHandlerRegistra[i];
		if ((handler->cmd == cmd) && (handler->endpointID == endpointID)){														
			pthread_mutex_lock(&handler->waitingMutex);
			pthread_cond_signal(&handler->waitingCond);
			pthread_mutex_unlock(&handler->waitingMutex);
			//-- remove the handler
			this->commandHandlerRegistra.erase(this->commandHandlerRegistra.begin() + i);
			break;
		}
	}
}

void* PacketHandler::processingLoop(void* args){

	PacketHandler* _this = (PacketHandler*)args;
	
	SVCPacket* packet = NULL;
	uint8_t infoByte;
	
	while (_this->working || _this->readingQueue->notEmpty()){	
		packet = _this->readingQueue->dequeueWait(1000);
		//-- process the packet
		if (packet!=NULL){						
			if (_this->packetHandler!=NULL){
				_this->packetHandler(packet, _this->packetHandlerArgs);
			}						
		}
		//else{//--TODO: can count dequeue fails to predict the network status}
	}	
	pthread_exit(EXIT_SUCCESS);
}



