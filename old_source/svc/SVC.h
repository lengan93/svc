/* Secure Virtual Connector (SVC) protocol header */

#ifndef __SVC__
#define __SVC__


	#include "authenticator/SVCAuthenticator.h"
	#include "MutexedQueue.h"
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
		
		public:
			~SVCEndPoint();
			
			void setEndPointID(uint64_t endPointID);
			int sendData(const uint8_t* data, size_t dalalen, uint8_t priority, bool tcp);
			int readData(uint8_t* data, size_t* len);
	};
	
	class SVC{						
		friend class SVCEndPoint;		
		private:				
			
			SVCApp* localApp;
			SVCAuthenticator* authenticator;
				
			shared_mutex* endPointsMutex;
			vector<SVCEndPoint*> endPoints;

			string svcClientPath;
			struct sockaddr_un daemonSocketAddress;		//--	write to
			struct sockaddr_un svcSocketAddress;		//--	read from
			int svcSocket;
			int svcDaemonSocket;

			pthread_t readingThread;
			volatile bool working;		
		
			MutexedQueue<Message*>* connectionRequest;
			uint32_t appID;

			void destruct();
			SVCEndPoint* getEndPointByID(uint64_t endPointID);
			
			static void* processPacket(void* args);
			//static void* processConnectionRequest(void* args);
			
		public:				
	
			~SVC();
			void stopWorking();
			SVC(SVCApp* localApp, SVCAuthenticator* authenticator);						
			SVCEndPoint* establishConnection(SVCHost* remoteHost);
			SVCEndPoint* listenConnection();					
	};		
	
#endif
