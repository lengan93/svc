/* Secure Virtual Connector (SVC) protocol header */

#ifndef __SVC__
#define __SVC__

	#include "svc-header.h"
	#include "svc-utils.h"
	#include "host/SVCHost.h"
	#include "authenticator/SVCAuthenticator.h"
	
	#include "../utils/Message.h"
	#include "../utils/MutexedQueue.h"
	#include "../crypto/SHA256.h"
	#include "../crypto/crypto-utils.h"
	
	#include <unistd.h>	//--	for unlink
	#include <sys/un.h> //--	for unix socket
	#include <cstring>  //--	for memcpy
	#include <unordered_map>

	using namespace std;
	
	//--	FORWARD DECLARATION		--//
	class SVC;
		
	class SVCEndpoint{				
		friend class SVC;
		
		static void endpoint_packet_handler(SVCPacket* packet, void* args);

		private:
			MutexedQueue<SVCPacket*>* dataQueue;
		
			SVC* svc;
			bool isInitiator;
			bool isAuth;
			volatile bool working;
			
			int sock;
			string endpointSockPath;
			uint64_t endpointID;
			uint32_t appID;
			PacketHandler* packetHandler;
			SVCHost* remoteHost;
			SVCPacket* request;
		
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
			int readData(uint8_t* data, uint32_t* len);
			
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
			static void svc_packet_handler(SVCPacket* packet, void* args);
			
			//-- private members
			SHA256* sha256;
			int appSocket;
			string appSockPath;
			
			unordered_map<uint64_t, SVCEndpoint*> endpoints;
			MutexedQueue<SVCPacket*>* connectionRequests;
			PacketHandler* packetHandler;
			volatile bool working;
			
			uint32_t appID;
			SVCAuthenticator* authenticator;
			
		public:
			
			/*
			 * Create a SVC instance which is used by 'appID' and has 'authenticator' as protocol authentication mechanism
			 * */
			SVC(string appID, SVCAuthenticator* authenticator);
						
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
