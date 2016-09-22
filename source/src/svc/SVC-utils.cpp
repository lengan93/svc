#include "SVC-utils.h"


//--	SIGNAL NOTIFICATOR class

SignalNotificator::SignalNotificator(){
	/*	need to init this array to NULL, otherwise left memory will cause addNotificator to throw exception	*/
	for (uint8_t cmd = 0; cmd<_SVC_CMD_COUNT; cmd++){
		this->notificationArray[cmd] = NULL;
	}			
}

void SignalNotificator::waitCommandHandler(const uint8_t* buffer, size_t datalen, void* args){
	struct SVCDataReceiveNotificator* notificator = (struct SVCDataReceiveNotificator*)args;	
	vector<SVCCommandParam*>* params = (vector<SVCCommandParam*>*)notificator->args;

	extractParams(buffer + ENDPOINTID_LENGTH + 2, params);
	//signal the thread calling waitCommand
	pthread_kill(notificator->thread, SVC_ACQUIRED_SIGNAL);
}

bool SignalNotificator::waitCommand(enum SVCCommand cmd, vector<SVCCommandParam*>* params, int timeout){
	//--	create new notificator
	clearParams(params);
	struct SVCDataReceiveNotificator* notificator = new struct SVCDataReceiveNotificator();
	notificator->args = params;
	notificator->thread = pthread_self();
	notificator->handler = waitCommandHandler;

	/*
		add this notificator to notificationList
		NOTE: To use 'waitCommand', make sure that there is at least one active thread
		which is processing the message and checking notificationList.
		use mutex to synchonize multiple threads which may use the list at a same time
	*/

	this->addNotificator(cmd, notificator);		

	//--	suspend the calling thread and wait for SVC_ACQUIRED_SIGNAL
	return waitSignal(SVC_ACQUIRED_SIGNAL, SVC_TIMEOUT_SIGNAL, timeout);
}

void SignalNotificator::addNotificator(enum SVCCommand cmd, SVCDataReceiveNotificator* notificator){
	notificationArrayMutex.lock();
	if (notificationArray[cmd]!=NULL){
		notificationArrayMutex.unlock();
		throw SVC_ERROR_NOTIFICATOR_DUPLICATED;
	}
	else{
		notificationArray[cmd] = notificator;
		notificationArrayMutex.unlock();
		//printf("noti added, cmd: %d\n", cmd);
	}					
}

void SignalNotificator::removeNotificator(enum SVCCommand cmd){
	notificationArrayMutex.lock();
	if (notificationArray[cmd]!=NULL){
		delete notificationArray[cmd];
		notificationArray[cmd]=NULL;
		//printf("noti removed, cmd: %d\n", cmd);
	}
	notificationArrayMutex.unlock();				
}

SVCDataReceiveNotificator* SignalNotificator::getNotificator(enum SVCCommand cmd){
	SVCDataReceiveNotificator* rs;
	notificationArrayMutex.lock_shared();
	rs = notificationArray[cmd];
	notificationArrayMutex.unlock_shared();
	return rs;
}



//--	UTILS FUNCTION IMPLEMEMTATION	--//

bool isEncryptedCommand(enum SVCCommand command){
	return (command != SVC_CMD_CHECK_ALIVE 
			&& command != SVC_CMD_CHECK_ALIVE
			&& command != SVC_CMD_CONNECT_STEP1
			&& command != SVC_CMD_CONNECT_STEP2
			&& command != SVC_CMD_CONNECT_STEP3);
}

void extractParams(const uint8_t* buffer, vector<SVCCommandParam*>* params){
	
	int argc = buffer[0];
	int pointer = 1;
	uint16_t len;
	
	for (int i=0; i<argc; i++){		
		len = *((uint16_t*)(buffer+pointer));
		params->push_back(new SVCCommandParam(len, buffer + pointer + 2));
		pointer += len+2;
	}
}

void clearParams(vector<SVCCommandParam*>* params){
	for (int i=0; i<params->size(); i++){
		delete (*params)[i];
	}
	params->clear();
}
