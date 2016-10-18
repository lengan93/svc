#ifndef	__SVC_UTILS__
#define __SVC_UTILS__

	#include "../utils/SharedMutex.h"
	#include "../utils/Message.h"
	#include "../utils/utils-functions.h"
	#include "SVC-header.h"
	
	#include <cstring>
	#include <vector>
	#include <sys/socket.h>

	//--	return if the command must be encrypted
	bool isEncryptedCommand(enum SVCCommand command);
	
	uint8_t* createSVCPacket(uint32_t dataLen);
	void setPacketCommand(uint8_t* packet, enum SVCCommand cmd);
	void addPacketParam(uint8_t* packet, const uint8_t* param, uint16_t paramLen);
	
	//-- utils classes
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
	
	class PacketHandler{
	
		class CommandHandler{
			public:
				uint64_t endpointID;
				enum SVCCommand cmd;
				pthread_t waitingThread;
				uint8_t* packet;
				uint32_t* packetLen;
		};
		
		private:
			//--	static methods
			static void* readingLoop(void* args);
			
			//--	members
			vector<CommandHandler> commandHandlerRegistra;
			int socket;
			bool working;
			pthread_t readingThread;
			SVCPacketProcessing cmdHandler;
			SVCPacketProcessing dataHandler;

		public:
			//--	constructors/destructors
			PacketHandler(int socket);
			virtual ~PacketHandler();
			
			//--	methods
			void setCommandHandler(SVCPacketProcessing cmdHandler);
			void setDataHandler(SVCPacketProcessing dataHandler);
			bool waitCommand(enum SVCCommand cmd, uint64_t endpointID, uint8_t* packet, uint32_t* packetLen, int timeout);
			int sendPacket(const uint8_t* packet, uint32_t packetLen);
			void stopWorking();
			void waitStop();
	};
	
#endif
