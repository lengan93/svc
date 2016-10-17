#include "SVC-utils.h"


//--	UTILS FUNCTION IMPLEMEMTATION	--//
bool isEncryptedCommand(enum SVCCommand command){
	return (command == SVC_CMD_CONNECT_OUTER3);
}

uint8_t* createSVCPacket(uint32_t dataLen){
	//-- 8 bytes endpointID + 1 byte info + 4 bytes sequence + data
	uint8_t* packet = (uint8_t*)malloc(SVC_PACKET_HEADER_LEN+dataLen);
	return packet;
}

void setPacketCommand(uint8_t* packet, enum SVCCommand cmd){
	//-- set info byte to be a command
	packet[8] |= 0x80;
	//-- set commandID
	packet[13] = (uint8_t)cmd;
	//-- reset number of param
	packet[14] = 0x00;
}

void addPacketParam(uint8_t* packet, const uint8_t* param, uint16_t paramLen){
	//-- find position of the new param
	uint8_t* p = packet + 15;
	for (uint8_t i=0; i<packet[14]; i++){
		p += 2 + *((uint16_t*)p);
	}
	//-- copy new param to packet
	memcpy(p, param, paramLen);
	//-- copy param length to p-2
	memcpy(p-2, (uint8_t*)&paramLen, 2);
	//-- add 1 to number of param
	packet[14] += 1;
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
}
void PeriodicWorker::stopWorking(){
	//--	disarm automatic
	working = false;
	pthread_join(this->worker, NULL);
	timer_delete(this->timer);
	printf("\nperiodic worker stopped");
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

PeriodicWorker::~PeriodicWorker(){
	printf("\nperiod worker detructed");
}

//--	PACKET HANDLER CLASS	--//
PacketHandler::PacketHandler(int socket){
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
}

void PacketHandler::waitStop(){
	pthread_join(this->readingThread, NULL);
}

void PacketHandler::stopWorking(){
	this->working = false;
}

void PacketHandler::setDataHandler(SVCPacketProcessing dataHandler){
	this->dataHandler = dataHandler;
}

void PacketHandler::setCommandHandler(SVCPacketProcessing cmdHandler){
	this->cmdHandler = cmdHandler;
}

void PacketHandler::sendPacket(const uint8_t* packet, uint32_t packetLen){
	send(this->socket, packet, packetLen, 0);
}

bool PacketHandler::waitCommand(enum SVCCommand cmd, uint64_t endpointID, uint8_t* packet, uint32_t* packetLen, int timeout){
	struct CommandHandler handler;
	handler.waitingThread = pthread_self();
	handler.cmd = cmd;
	handler.endpointID = endpointID;
	handler.packet = packet;
	handler.packetLen = packetLen;
	commandHandlerRegistra.push_back(handler);
	
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
	
	int byteRead;
	uint8_t* buffer = (uint8_t*)malloc(SVC_DEFAULT_BUFSIZ);
		
	while (_this->working){
		do{
			byteRead = recv(_this->socket, buffer, SVC_DEFAULT_BUFSIZ, 0);		
		}
		while((byteRead==-1) && _this->working);
		
		if (byteRead>0){
			uint8_t infoByte = buffer[ENDPOINTID_LENGTH];
			if (infoByte & SVC_COMMAND_FRAME){
					if (infoByte & SVC_ENCRYPTED == 0x00){
						//-- this command is not encrypted, get the commandID						
						enum SVCCommand cmd = (enum SVCCommand)buffer[SVC_PACKET_HEADER_LEN];
						uint64_t endpointID = *((uint64_t*)&buffer);
						//-- check if the cmd is registered in the registra
						for (int i=0;i<_this->commandHandlerRegistra.size(); i++){
							if (_this->commandHandlerRegistra[i].cmd == cmd && _this->commandHandlerRegistra[i].endpointID == endpointID){
								//-- copy the packet content and notify the suspended thread
								memcpy(_this->commandHandlerRegistra[i].packet, buffer, byteRead);
								*(_this->commandHandlerRegistra[i].packetLen) = byteRead;
								pthread_kill(_this->commandHandlerRegistra[i].waitingThread, SVC_ACQUIRED_SIGNAL);
								//-- remove the handler
								_this->commandHandlerRegistra.erase(_this->commandHandlerRegistra.begin() + i);							
							}
						}
					}
					//-- call handler routine for command
					if (_this->cmdHandler!=NULL) _this->cmdHandler(buffer, byteRead);
			}
			else{
					//-- call handler routine for data
					if (_this->dataHandler!=NULL) _this->dataHandler(buffer, byteRead);
			}			
		}
	}
	
	delete buffer;
}

