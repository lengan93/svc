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
}

void* PeriodicWorker::handling(void* args){
	
	PeriodicWorker* pw = (PeriodicWorker*)args;
	
	struct sigevent evt;
	evt.sigev_notify = SIGEV_SIGNAL;
	evt.sigev_signo = SVC_PERIODIC_SIGNAL;
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
		waitrs = waitSignal(SVC_PERIODIC_SIGNAL);
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
	//-- can only be interrupted by SIGINT
	pthread_kill(this->worker, SIGINT);
	pthread_join(this->worker, NULL);
}

PeriodicWorker::~PeriodicWorker(){
	if (this->working){
		this->stopWorking();
		this->waitStop();
	}
	printf("\nperiod worker detructed");
}

//--	PACKET HANDLER CLASS	--//
PacketHandler::PacketHandler(int socket){
	printf("\nnew packet handler created for socket %d", socket); fflush(stdout);
	this->socket = socket;
	this->working = true;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_create(&this->readingThread, &attr, readingLoop, this);
}

PacketHandler::~PacketHandler(){
	if (this->working){
		stopWorking();
		waitStop();
	}
	printf("\npacket handler %d stopped", this->socket); fflush(stdout);
}

void PacketHandler::waitStop(){
	pthread_join(this->readingThread, NULL);
}

void PacketHandler::stopWorking(){
	this->working = false;
}

void PacketHandler::setDataHandler(SVCPacketProcessing dataHandler, void* args){
	this->dataHandler = dataHandler;
	this->dataHandlerArgs = args;
}

void PacketHandler::setCommandHandler(SVCPacketProcessing cmdHandler, void* args){
	this->cmdHandler = cmdHandler;
	this->cmdHandlerArgs = args;
}

int PacketHandler::sendPacket(SVCPacket* packet){
	//printf("\npacket handler %d sending: ", this->socket); printBuffer(packet, packetLen); fflush(stdout);
	return send(this->socket, packet->packet, packet->dataLen, 0);
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
		return waitSignal(SVC_ACQUIRED_SIGNAL, SVC_TIMEOUT_SIGNAL, timeout);
	}
	else{
		return waitSignal(SVC_ACQUIRED_SIGNAL);
	}
}

void* PacketHandler::readingLoop(void* args){
	
	PacketHandler* _this = (PacketHandler*)args;
	uint8_t* buffer = (uint8_t*)malloc(SVC_DEFAULT_BUFSIZ);
	ssize_t readrs;
	
	while (_this->working){
		do{
			readrs = recv(_this->socket, buffer, SVC_DEFAULT_BUFSIZ, MSG_DONTWAIT); // in case interrupted by SIGINT, MSG_DONTWAIT helps exit the loop
		}
		while((readrs==-1) && _this->working);
		
		if (readrs>0){
			SVCPacket* packet = new SVCPacket(buffer, readrs);			
			//printf("\npacket handler %d read: ", _this->socket); printBuffer(packet->packet, packet->dataLen); fflush(stdout);
			uint8_t infoByte = packet->packet[ENDPOINTID_LENGTH];
			if ((infoByte & SVC_COMMAND_FRAME) != 0){				
				if ((infoByte & SVC_ENCRYPTED) == 0){				
					//-- this command is not encrypted, get the commandID					
					enum SVCCommand cmd = (enum SVCCommand)packet->packet[SVC_PACKET_HEADER_LEN];					
					uint64_t endpointID = *((uint64_t*)packet->packet);					
					//-- check if the cmd is registered in the registra
					for (int i=0;i<_this->commandHandlerRegistra.size(); i++){
						if (_this->commandHandlerRegistra[i].cmd == cmd && _this->commandHandlerRegistra[i].endpointID == endpointID){							
							//-- copy the packet content and notify the suspended thread
							memcpy(_this->commandHandlerRegistra[i].packet->packet, packet->packet, packet->dataLen);
							_this->commandHandlerRegistra[i].packet->dataLen = packet->dataLen;
							pthread_kill(_this->commandHandlerRegistra[i].waitingThread, SVC_ACQUIRED_SIGNAL);
							//-- remove the handler
							_this->commandHandlerRegistra.erase(_this->commandHandlerRegistra.begin() + i);							
						}
					}
				}				
				//-- call handler routine for command
				if (_this->cmdHandler!=NULL) _this->cmdHandler(packet, _this->cmdHandlerArgs);
			}
			else{
				//-- call handler routine for data
				if (_this->dataHandler!=NULL) _this->dataHandler(packet, _this->dataHandlerArgs);
			}			
		}
	}
	
	delete buffer;
}

