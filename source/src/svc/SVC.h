/* Secure Virtual Connector (SVC) protocol header */

#ifndef __SVC__
#define __SVC__

	#include "svc-utils.h"
	#include "host/SVCHost.h"
	#include "authenticator/SVCAuthenticator.h"
	
	#include "../utils/MutexedQueue.h"
	#include "../crypto/SHA256.h"
	#include "../crypto/crypto-utils.h"
	
	#include <csignal>
	#include <sys/un.h>
	#include <sys/socket.h>	
	#include <unordered_map>

	//--	FORWARD DECLARATION		--//
	class SVC;
		
	class SVCEndpoint{				
		friend class SVC;
		
		static void endpoint_packet_handler(SVCPacket* packet, void* args);

		private:			
		
			SVC* svc;
			bool isInitiator;
			bool isAuth;
			
			volatile bool working;
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
			std::string endpointSockPath;
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
		
			SVCEndpoint(SVC* svc, bool isInitiator);	
			
			/*
			 * Connect the unix domain socket to the daemon endpoint address to send data
			 * */
			int connectToDaemon();	
						
			/*
			 * */
			void setRemoteHost(SVCHost* remoteHost);
			
			/*
			 * */
			void changeEndpointID(uint64_t endpointID);
			
			/*
			 * */
			int bindToEndpointID(uint64_t endpointID);

		public:
			~SVCEndpoint();
			/*
			 * Start negotiating and return TRUE if the protocol succeeds, otherwise return FALSE
			 * */
			bool negotiate();
			
			/*
			 * Send data over the connector to the other endpoint of communication.
			 * The data will be automatically encrypted by the under layer
			 * */
			int sendData(const uint8_t* data, uint32_t dalalen, uint8_t priority, bool tcp);
			
			/*
			 * Read data from the buffer. The data had already been decrypted.
			 * */
			int readData(uint8_t* data, uint32_t* len, int timeout);
			
			/*
			 * Close the communication endpoint and send terminate signals to underlayer
			 * */
			void shutdown();
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
			std::string appSockPath;						
						
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
			SVCEndpoint* establishConnection(SVCHost* remoteHost);
			
			/*
			 * 'listenConnection' reads in the connection request queue and returns immediately if a request is found
			 * If there is no connection request, 'listenConnection' will wait for 'timeout' milisecond before return NULL		
			 * On success, a pointer to SVCEndpoint is returned
			 * Like 'establishConnection', the negotiation should be processed in a seperated thread
			 * */
			SVCEndpoint* listenConnection(int timeout);
			
			/*
			 * try to shutdown all created instances of SVCEndpoint then shutdown itself
			 * */
			void shutdown();
	};
	
#endif
