/* Secure Virtual Connector (SVC) protocol header */

#ifndef __SVC__
#define __SVC__

	#include "../utils/MutexedQueue.h"
	#include "authenticator/SVCAuthenticator.h"
	#include "host/SVCHost.h"
	#include "SVCApp.h"

	#include <unistd.h>	//--	for unlink
	#include <sys/un.h>

	using namespace std;
	
	static hash<string> hasher;
	
	//--	FORWARD DECLARATION		--//
	class SVC;
	
	class SVCEndPoint{			
		friend class SVC;			
		private:			
			struct sockaddr_un endPointSocketAddress;
			int endPointSocket;			
			MutexedQueue<Message*>* dataQueue;			
			SVC* svc;
			uint64_t endPointID;
			SignalNotificator* signalNotificator;
			
			SVCEndPoint(SVC* svc);
			void sendCommand(enum SVCCommand cmd, vector<SVCCommandParam*>* params);
			void setEndPointID(uint64_t endPointID);
			
		public:
			~SVCEndPoint();						
			int sendData(const uint8_t* data, size_t dalalen, uint8_t priority, bool tcp);
			int readData(uint8_t* data, size_t* len);
	};
	
	class SVC{
		friend class SVCEndPoint;		
		private:			 
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
			static void* processPacket(void* args);	
			
			SVCEndPoint* getEndPointByID(uint64_t endPointID);
			void SVC::removeEndPointByID(uint64_t endPointID)
							
			void destruct();
			
		public:				
			~SVC();			
			SVC(string appID, SVCAuthenticator* authenticator);
			SVCEndPoint* establishConnection(SVCHost* remoteHost);
			SVCEndPoint* listenConnection();
	};
	
#endif
