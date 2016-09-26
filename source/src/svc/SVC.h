/* Secure Virtual Connector (SVC) protocol header */

#ifndef __SVC__
#define __SVC__

	#include "../utils/Message.h"
	#include "../utils/MutexedQueue.h"
	#include "SVC-header.h"
	#include "SVC-utils.h"
	#include "host/SVCHost.h"
	#include "authenticator/SVCAuthenticator.h"
	
	#include <unistd.h>	//--	for unlink
	#include <sys/un.h>

	using namespace std;
	
	static hash<string> hasher;
	
	//--	FORWARD DECLARATION		--//
	class SVC;
	
	class SVCEndPoint{			
		friend class SVC;
		
		MutexedQueue<Message*>* dataQueue;
		
		SVC* svc;			
		uint64_t endPointID;							
		SignalNotificator* signalNotificator;	
		
		private:						
			SVCEndPoint(SVC* svc, SignalNotificator* sigNot);
			void sendCommand(enum SVCCommand cmd, vector<Message*>* params);
			
		public:
			~SVCEndPoint();						
			int sendData(const uint8_t* data, size_t dalalen, uint8_t priority, bool tcp);
			int readData(uint8_t* data, size_t* len);
	};
	
	class SVC{
		friend class SVCEndPoint;
		
		SVCAuthenticator* authenticator;
		uint32_t hashAppID;
		
		SharedMutex* endPointsMutex;
		vector<SVCEndPoint*> endPoints;
		MutexedQueue<Message*>* connectionRequest;

		string svcClientPath;
		struct sockaddr_un daemonSocketAddress;
		struct sockaddr_un svcSocketAddress;
		int svcSocket;
		pthread_t readingThread;
		volatile bool working;
		
		private:			 		
			static void* processPacket(void* args);				
			SVCEndPoint* getEndPointByID(uint64_t endPointID);
			void removeEndPointByID(uint64_t endPointID);							
			void destruct();
			
		public:				
			~SVC();			
			SVC(string appID, SVCAuthenticator* authenticator);
			SVCEndPoint* establishConnection(SVCHost* remoteHost);
			SVCEndPoint* listenConnection();
	};
	
#endif
