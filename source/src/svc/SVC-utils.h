#ifndef	__SVC_UTILS__
#define __SVC_UTILS__

	#include "SharedMutex.h"
	#include "SVC-header.h"
	#include <cstring>
	#include <vector>
	#include <sys/time.h>
	#include <sys/socket.h>

	typedef void (*SVCDataReceiveHandler)(const Message* message, void* args);
	
	struct SVCDataReceiveNotificator{
		SVCDataReceiveHandler handler;
		void* args;
		pthread_t thread;			
	};
	
	class SignalNotificator;

	//--	return if the command must be encrypted
	bool isEncryptedCommand(enum SVCCommand command);

	//--	clear all params in the vector and call their destructors
	void clearParams(vector<SVCCommandParam*>* params);

	//--	extract parameters from a buffer without header
	void extractParams(const uint8_t* buffer, vector<SVCCommandParam*>* params);


	//--	just make sure that there will be no wait for 2 same cmd on a single list
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
