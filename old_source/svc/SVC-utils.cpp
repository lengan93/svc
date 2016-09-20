#include "SVC-utils.h"

//--	MESSAGE class
			
Message::Message(const uint8_t* data, size_t len){
	this->data = (uint8_t*)malloc(SVC_DEFAULT_BUFSIZ);
	this->len = len;
	memcpy(this->data, data, this->len);
}

Message::~Message(){
	delete data;
	//printf("message destructed\n");
}

//--	SVCCOMMANDPARAM class
SVCCommandParam::SVCCommandParam(){
	this->copy = false;
}

SVCCommandParam::SVCCommandParam(uint16_t length, const uint8_t* data){
	this->len = length;
	this->data = (uint8_t*)malloc(len);
	memcpy(this->data, data, len);
	this->copy = true;
}

SVCCommandParam::~SVCCommandParam(){	
	if (this->copy){
		delete this->data;
		//printf("param destructed\n");
	}
}

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

bool waitSignal(int waitingSignal){
	sigset_t sig;
	sigemptyset(&sig);
	sigaddset(&sig, waitingSignal);
	sigaddset(&sig, SIGINT);	//--	interupt case
	
	int caughtSignal;
	sigwait(&sig, &caughtSignal);	
	return waitingSignal == caughtSignal;
}

bool waitSignal(int waitingSignal, int timeoutSignal, int timeout){
	
	sigset_t sig;
	sigemptyset(&sig);
	sigaddset(&sig, waitingSignal);
	sigaddset(&sig, timeoutSignal);	
	
	timer_t timer;
	struct sigevent evt;
	evt.sigev_notify = SIGEV_SIGNAL;
	evt.sigev_signo = timeoutSignal;
	evt.sigev_notify_thread_id = pthread_self();
	timer_create(CLOCK_REALTIME, &evt, &timer);
	
	struct itimerspec time;
	time.it_interval.tv_sec=0;
	time.it_interval.tv_nsec=0;	
	time.it_value.tv_sec=timeout/1000;
	time.it_value.tv_nsec=(timeout - time.it_value.tv_sec*1000)*1000000;	
	timer_settime(timer, 0, &time, NULL);
	
	//--	wait for either timeoutSignal or watingSignal
	int caughtSignal;
	sigwait(&sig, &caughtSignal);
	
	return caughtSignal == waitingSignal;	
}

void printBuffer(const uint8_t* buffer, size_t len){

	for (int i=0; i<len; i++){
		printf("%02x ", buffer[i]);
	}
}
