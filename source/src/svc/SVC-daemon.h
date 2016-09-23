#ifndef __SVC_DAEMON_HEADER__
#define __SVC_DAEMON_HEADER__

	#define SVC_VERSION 0x01
	/*
	 * SVC DAEMON IMPLEMENTATION
	 * THE VERSION MUST BE CHANGED APPROPRIATELY	 
	 * */
	

	#include "../utils/MutexedQueue.h"
	#include "../utils/PeriodicWorker.h"
	#include "SVC-utils.h"
	#include "SVC-header.h"
	
	#include <string>
	#include <iostream>
	#include <unistd.h>
	#include <cstdlib>
	#include <csignal>
	#include <iostream>

	#include <sys/ipc.h>
	#include <sys/msg.h>
	#include <sys/socket.h>
	#include <sys/un.h>
	#include <sys/types.h>
	#include <netinet/in.h>

	using namespace std;
	
	//--	forward class declaration
	class DaemonEndPoint;
	class DaemonService;

	static vector<DaemonService*> serviceTable;
	static SharedMutex* serviceTableMutex;
	static hash<string> hasher;

	struct sockaddr_un daemonSockUnAddress;
	struct sockaddr_in daemonSockInAddress;
	int daemonUnSocket;
	int daemonInSocket;

	pthread_t unixReadingThread;
	pthread_t htpReadingThread;
	pthread_attr_t htpReadingThreadAttr;
	pthread_attr_t unixReadingThreadAttr;
	uint8_t* htpReceiveBuffer;
	uint8_t* unixReceiveBuffer;

	string errorString;
	volatile bool working;

	class DaemonService{
	
		friend class DaemonEndPoint;
		private:
			bool isConnected;
			volatile bool working;
		
			struct sockaddr_in sockAddr;
			socklen_t sockLen;
			PeriodicWorker* threadCheckAlive;

			//--	CRYPTO VARIABLES	--//
			static void checkAliveEndPoint(void* args);
			void sendData(const uint8_t* buffer, size_t bufferLen);	
			bool encryptMessage(const uint8_t* plainMessage, size_t plainLen, uint8_t* encryptedMessage, size_t* encryptedLen);		
			bool decryptMessage(const uint8_t* encryptedMessage, size_t encryptedLen, uint8_t* plainMessage, size_t* plainLen);		
	
		public:
			vector<DaemonEndPoint*> endPoints;
			SharedMutex* endPointsMutex;
			uint32_t sessionID;
			uint32_t address;
		
			DaemonService(const struct sockaddr_in* sockaddr, socklen_t sockLen);
			~DaemonService();
		
			bool isWorking();		
			void stopWorking();
			void removeDaemonEndPoint(uint64_t endPointID);
			DaemonEndPoint* addDaemonEndPoint(uint64_t endPointID, uint32_t appID);
			DaemonEndPoint* getDaemonEndPoint(uint64_t endPointID);
	};

	class DaemonEndPoint{

		friend class DaemonService;
		private:
			DaemonService* daemonService;
			
			pthread_attr_t threadAttr;
			pthread_t processIncomingThread;
			pthread_t processOutgoingThread;
			pthread_t sendInThread;
			pthread_t sendOutThread;
			volatile bool working;
			
			int liveTime;
			bool isAuthenticated;			
					
			struct sockaddr_un unSockAddr;
			int unSock;
			
			static void* processingIncomingMessage(void* args);	
			static void* processingOutgoingMessage(void* args);
			static void* sendPacketToApp(void* args);
			static void* sendPacketOutside(void* args);
			
			static Message* checkAliveMessage;
			
			void sendCheckAlive();		

		public:
			uint64_t endPointID;
			uint32_t appID;
			MutexedQueue<Message*>* incomingQueue;
			MutexedQueue<Message*>* outgoingQueue;
			MutexedQueue<Message*>* inQueue;
			MutexedQueue<Message*>* outQueue;
			
			DaemonEndPoint(DaemonService* daemonService, uint64_t endPointID, uint32_t appID);
			~DaemonEndPoint();
		
			void stopWorking();				
	};

	void* unixReadingLoop(void* args);
	void* htpReadingLoop(void* args);


	//--	HELPER FUNCTIONS	--//
	DaemonService* getServiceByAddress(uint32_t address);
	DaemonService* getServiceBySessionID(uint32_t sessionID);
		DaemonService* getServiceByEndPointID(uint64_t endPOintID);
	void signal_handler(int sig);
	//---------------------------//
	
#endif
