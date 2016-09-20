#ifndef	__SVC_UTILS__
#define __SVC_UTILS__

	#include "shared_mutex.h"
	#include "SVC-header.h"
	#include <cstring>
	#include <vector>
	#include <sys/time.h>
	#include <sys/socket.h>

	typedef void (*SVCDataReceiveHandler)(const uint8_t* data, size_t datalen, void* args);
	
	struct SVCDataReceiveNotificator{
		SVCDataReceiveHandler handler;
		void* args;
		pthread_t thread;			
	};
	
	//--	class forward declaration	
	class SVCCommandParam;
	class PeriodicWorker;
	class Message;
	class SignalNotificator;

	//--	UTILS FUNCTIONS		--//
	
	//--	return if the command must be encrypted
	bool isEncryptedCommand(enum SVCCommand command);

	//--	clear all params in the vector and call their destructors
	void clearParams(vector<SVCCommandParam*>* params);

	//--	extract parameters from a buffer without header
	void extractParams(const uint8_t* buffer, vector<SVCCommandParam*>* params);

	//--	print current buffer in hex bytes
	void printBuffer(const uint8_t* buffer, size_t len);

	//--	timeoutSignal and waitingSignal must be differrent, otherwise the behavior is undefined
	bool waitSignal(int waitingSignal, int timeoutSignal, int timeout);
	bool waitSignal(int waitingSignal);
	
	//--	CLASS DECLARATION	--//
	class PeriodicWorker{
		private:
			timer_t timer;
			pthread_t worker;
			volatile bool working;
			void (*handler)(void*);
			void* args;
			int interval;
			
			static void* handling(void* args);
			
		public:
			PeriodicWorker(int interval, void (*handler)(void* args), void* args);
			~PeriodicWorker();			
			void stopWorking();
	};

	class Message{
		public:
			uint8_t* data;
			size_t len;
			
			Message(const uint8_t* data, size_t len);			
			~Message();	
	};

	class SVCCommandParam{
	
		bool copy;
		public:
			uint16_t len;
			uint8_t* data;
						
			SVCCommandParam();
			~SVCCommandParam();		
			SVCCommandParam(uint16_t length, const uint8_t* data);			
	};

	/*	just make sure that there will be no wait for 2 same cmd on a single list	*/	
	class SignalNotificator{
		private:			
			struct SVCDataReceiveNotificator* notificationArray[_SVC_CMD_COUNT];
			shared_mutex notificationArrayMutex;			
			static void waitCommandHandler(const uint8_t* buffer, size_t datalen, void* args);
			
		public:
			SignalNotificator();
			~SignalNotificator(){}
			
			SVCDataReceiveNotificator* getNotificator(enum SVCCommand cmd);			
			void removeNotificator(enum SVCCommand cmd);
			void addNotificator(enum SVCCommand cmd, SVCDataReceiveNotificator* notificator);			
			bool waitCommand(enum SVCCommand cmd, vector<SVCCommandParam*>* params, int timeout);
	};			
	
#endif
