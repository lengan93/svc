/* Secure Virtual Connector (SVC) protocol header */

#ifndef __SVC__
#define __SVC__

	// #include <csignal>
	// #include <sys/un.h>
	// #include <sys/socket.h>
	// #include <unordered_map>

	// #include "svc-utils.h"
	#include "host/SVCHost.h"
	#include "authenticator/SVCAuthenticator.h"
	
	#include "../utils/NamedPipe.h"
	#include "../utils/MutexedQueue.h"
	// #include "../utils/PeriodicWorker.h"
	// #include "../crypto/SHA256.h"
	// #include "../crypto/crypto-utils.h"
	
	// #define RECONNECTION_TIMEOUT	5000

	class SVC;
		
	class SVCEndpoint{
		friend class SVC;

		private:
		
			// SVC* svc;
			// bool isInitiator;
			// bool isAuth;
			// PeriodicWorker* periodicWorker;
			
			// volatile bool working;
			// volatile bool shutdownCalled;
			// int reconnectionTimeout;			
			// bool reconnectFailed;
			// //string daemonRestartReason;

			// static void liveCheck(void* args);		
			// static void svc_endpoint_incoming_packet_handler(SVCPacket* packet, void* args);
			// //static void svc_endpoint_outgoing_packet_handler(SVCPacket* packet, void* args);
			// static void* svc_endpoint_reading_loop(void* args);
			// static void* svc_endpoint_writing_loop(void* args);
			
			// pthread_t readingThread;
			// pthread_t writingThread;
			// //MutexedQueue<SVCPacket*> incomingQueue;
			// //MutexedQueue<SVCPacket*> outgoingQueue;
			// MutexedQueue<SVCPacket*>* tobesentQueue;
			// MutexedQueue<SVCPacket*>* dataholdQueue;
			// PacketHandler* incomingPacketHandler;
			// //PacketHandler* outgoingPacketHandler;
			
			// int sock;
			// int sockOption;
			// uint64_t endpointID;
			// uint32_t appID;			
			// SVCHost* remoteHost;
			// SVCPacket* request;
			
			// //-- crypto negotitation
			// std::string challengeSecretSent;
			// std::string challengeSecretReceived;
			// std::string challengeSent;
			// std::string challengeReceived;
			// std::string proof;
			// std::string remoteIdentity;
		
			// SVCEndpoint(SVC* svc, uint64_t endpointID, bool isInitiator);	
			
			// /*
			//  * Connect the unix domain socket to the daemon endpoint address to send data
			//  * */
			// int connectToDaemon();
			
			// /*
			//  * After a disconnection with daemon is detected, calling this method will try to reconnect with the daemon. 
			//  * If TRUE is returned,the reconnection succeeded. Otherwise, the reconnection
			//  * is failed and SVC must be shutdown. The default waiting time can be set via setReconnectionTimeout.
			//  * */
			// bool reconnectDaemon();
			
			// /*
			//  * */
			// void setRemoteHost(SVCHost* remoteHost);
			
			// /*
			//  * */
			// void changeEndpointID(uint64_t endpointID);			

		public:
			~SVCEndpoint();
			bool negotiate();
			std::string getEndpointID();
			int sendData(const uint8_t* data, uint32_t datalen, uint8_t option);
			int readData(uint8_t* data, uint32_t* len, int timeout);
			void shutdown();
	};
	
	class SVC{
		friend class SVCEndpoint;

		private:
			uint32_t appID;
			SVCAuthenticator* authenticator;

			NamedPipe* daemonPipe;
			NamedPipe* svcPipe;
			
			pthread_t readingThread;
			MutexedQueue<SVCPacket*>* incomingQueue;
			PacketHandler* incomingPacketHandler;
			static void svc_incoming_packet_handler(SVCPacket* packet, void* args);

			// static void* svc_reading_loop(void* args);
			// //static void* svc_writing_loop(void* args);
			
			// //-- private members
			// inline void sendPacketToDaemon(SVCPacket* packet);
			
			// volatile bool working;
			// volatile bool shutdownCalled;
			
			// //pthread_t writingThread;
			
			// //MutexedQueue<SVCPacket*>* outgoingQueue;
			// //MutexedQueue<SVCPacket*>* tobesentQueue;
			// MutexedQueue<SVCPacket*>* connectionRequests;
			// //PacketHandler* outgoingPacketHandler;
															
			// unordered_map<uint128_t, SVCEndpoint*> endpoints;	
			
		public:
			SVC(const std::string& appIdentity, const SVCAuthenticator* authenticator);
			~SVC();
			SVCEndpoint* establishConnection(int timeout, SVCHost* remoteHost, uint8_t option);
			SVCEndpoint* listenConnection(int timeout, SVCHost* remoteHost);
	};
	
#endif
