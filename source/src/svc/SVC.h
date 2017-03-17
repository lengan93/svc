/* Secure Virtual Connector (SVC) protocol header */

#ifndef __SVC__
#define __SVC__

	#include "svc-utils.h"
	#include "host/SVCHost.h"
	#include "authenticator/SVCAuthenticator.h"
	
	#include "../crypto/SHA256.h"
	#include "../crypto/crypto-utils.h"
	#include "../utils/NamedPipe.h"
	#include "../utils/MutexedQueue.h"

	using namespace svc_utils;
	using namespace crypto;

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
			uint64_t endpointID;
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
		
			SVCEndpoint(SVC* svc, uint64_t endpointID, bool isInitiator);	
			
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
			uint64_t getEndpointID();
			int sendData(const uint8_t* data, uint16_t datalen, uint8_t option);
			int readData(uint8_t* data, uint16_t* len, int timeout);
			void shutdown();
	};
	
	class SVC{
		friend class SVCEndpoint;

		private:
			uint32_t appID;
			SVCAuthenticator* authenticator;

			NamedPipe* daemonPipe;
			NamedPipe* svcPipe;
			
			SVCPacketReader* packetReader;
			MutexedQueue<SVCPacket*>* incomingQueue;
			MutexedQueue<SVCPacket*>* connectionRequests;
			SVCPacketHandler* packetHandler;
			static void svc_incoming_packet_handler(SVCPacket* packet, void* args);

			volatile bool working;
			volatile bool shutdownCalled;
			void cleanUp();
			
		public:
			SVC(const std::string& appIdentity, SVCAuthenticator* authenticator);
			~SVC();
			void shutdown();
			SVCEndpoint* establishConnection(int timeout, SVCHost* remoteHost, uint8_t option);
			SVCEndpoint* listenConnection(int timeout, SVCHost* remoteHost);
	};
	
#endif
