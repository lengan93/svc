/* Secure Virtual Connector (SVC) protocol header */

#ifndef __SVC__
#define __SVC__

	#include "svc-utils.h"
	#include "host/SVCHost.h"
	#include "authenticator/SVCAuthenticator.h"
	
	#include "../utils/MutexedQueue.h"
	#include "../utils/PeriodicWorker.h"
	#include "../crypto/SHA256.h"
	#include "../crypto/crypto-utils.h"
	
	#include <csignal>
	#include <sys/un.h>
	#include <sys/socket.h>	
	#include <unordered_map>
	
	#define RECONNECTION_TIMEOUT	5000

	//--	FORWARD DECLARATION		--//
	class SVC;
		
	class SVCEndpoint{				
		friend class SVC;
			

		private:			
		
			SVC* svc;
			bool isInitiator;
			bool isAuth;
			PeriodicWorker* periodicWorker;
			
			volatile bool working;
			volatile bool shutdownCalled;
			int reconnectionTimeout;			
			bool reconnectFailed;
			string daemonRestartReason;

			static void liveCheck(void* args);		
			static void svc_endpoint_incoming_packet_handler(SVCPacket* packet, void* args);
			static void svc_endpoint_outgoing_packet_handler(SVCPacket* packet, void* args);
			static void* svc_endpoint_reading_loop(void* args);
			static void* svc_endpoint_writing_loop(void* args);

			
			pthread_t readingThread;
			pthread_t writingThread;			
			MutexedQueue<SVCPacket*> incomingQueue;
			MutexedQueue<SVCPacket*> outgoingQueue;
			MutexedQueue<SVCPacket*> tobesentQueue;
			MutexedQueue<SVCPacket*> dataholdQueue;
			PacketHandler* incomingPacketHandler;
			PacketHandler* outgoingPacketHandler;
			
			int sock;
			uint64_t endpointID;
			uint32_t appID;			
			SVCHost* remoteHost;
			SVCPacket* request;
			
			//-- crypto negotitation
			std::string challengeSecretSent;
			std::string challengeSecretReceived;
			std::string challengeSent;
			std::string challengeReceived;
			std::string proof;
			std::string remoteIdentity;
		
			SVCEndpoint(SVC* svc, uint64_t endpointID, bool isInitiator);	
			
			/*
			 * Connect the unix domain socket to the daemon endpoint address to send data
			 * */
			int connectToDaemon();
			
			/*
			 * After a disconnection with daemon is detected, calling this method will try to reconnect with the daemon. 
			 * If TRUE is returned,the reconnection succeeded. Otherwise, the reconnection
			 * is failed and SVC must be shutdown. The default waiting time can be set via setReconnectionTimeout.
			 * */
			bool reconnectDaemon();
			
			/*
			 * */
			void setRemoteHost(SVCHost* remoteHost);
			
			/*
			 * */
			void changeEndpointID(uint64_t endpointID);			

		public:
			~SVCEndpoint();
			/*
			 * Start negotiating and return TRUE if the protocol succeeds, otherwise return FALSE
			 * */
			bool negotiate();
			
			/*
			 *
			 * */
			std::string getRemoteIdentity();
						
			/*
			 * Send data over the connector to the other endpoint of communication.
			 * The data will be automatically encrypted by the under layer
			 * */			 						 
			int sendData(const uint8_t* data, uint32_t dalalen);
			
			/*
			 * Read data from the buffer. The data had already been decrypted.
			 * */
			int readData(uint8_t* data, uint32_t* len, int timeout);
			
			/*
			 * Close the communication endpoint and send terminate signals to underlayer
			 * */
			void shutdownEndpoint();
			
			/*
			 * Set the timeout of reconnection method in case of losing connection with the daemon. 'timeout' default to 5s and cannot be set to negative.
			 * */
			void setReconnectionTimeout(int timeout = RECONNECTION_TIMEOUT);
			
			bool isAlive(){
				return this->isAuth;
			}
	};
	
	class SVC{
		friend class SVCEndpoint;

		private:
			//-- static members
			static uint16_t endpointCounter;
			
			static void svc_incoming_packet_handler(SVCPacket* packet, void* args);
			static void svc_outgoing_packet_handler(SVCPacket* packet, void* args);
			static void* svc_reading_loop(void* args);
			static void* svc_writing_loop(void* args);
			
			volatile bool working;
			volatile bool shutdownCalled;
			pthread_t readingThread;
			pthread_t writingThread;			
			MutexedQueue<SVCPacket*> incomingQueue;
			MutexedQueue<SVCPacket*> outgoingQueue;
			MutexedQueue<SVCPacket*> tobesentQueue;
			MutexedQueue<SVCPacket*> connectionRequests;			
			
			PacketHandler* incomingPacketHandler;
			PacketHandler* outgoingPacketHandler;
			
									
			//-- private members
			unordered_map<uint64_t, SVCEndpoint*> endpoints;
			
			SHA256* sha256;
			int appSocket;
						
			uint32_t appID;
			SVCAuthenticator* authenticator;
			
		public:
			
			/*
			 * Create a SVC instance which is used by 'appID' and has 'authenticator' as protocol authentication mechanism
			 * */
			SVC(std::string appID, SVCAuthenticator* authenticator);
						
			~SVC();
			
			/*
			 * establishConnection immediately returns a pointer of SVCEndpoint that will later be used to perform the protocol's negotiation
			 * Because the negotiation takes time, it is highly recommended to start it in a seperated thread
			 * */
			SVCEndpoint* establishConnection(SVCHost* remoteHost, uint8_t option);
			
			/*
			 * 'listenConnection' reads in the connection request queue and returns immediately if a request is found
			 * If there is no connection request, 'listenConnection' will wait for 'timeout' milisecond before return NULL		
			 * On success, a pointer to SVCEndpoint is returned
			 * */
			SVCEndpoint* listenConnection(int timeout);
			
			/*
			 * try to shutdown all created instances of SVCEndpoint then shutdown itself
			 * */
			void shutdownSVC();
	};
	
#endif
