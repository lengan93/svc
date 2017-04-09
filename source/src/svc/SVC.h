/* Secure Virtual Connector (SVC) protocol header */

#ifndef __SVC__
#define __SVC__

	#include "svc-utils.h"
	#include "authenticator/SVCAuthenticator.h"
	
	#include "../crypto/SHA256.h"
	#include "../crypto/crypto-utils.h"
	#include "../utils/NamedPipe.h"
	#include "../utils/MutexedQueue.h"

	using namespace svc_utils;
	using namespace crypto;

	class SVC;

	class ChallengeSet {
		public:
			std::string challengeSecretSent;
			std::string challengeSent;
			std::string challengeSecretReceived;
			std::string challengeReceived;
			std::string proofSent;
			std::string proofReceived;
			std::string remoteIdentity;
	};
		
	class SVCEndpoint : public DataEndpoint{
		friend class SVC;

		private:
			SVC* svc;
			bool isInitiator;
			volatile bool working;
			bool isAuth;
			uint64_t pipeID;
			SVCPacket* requestPacket;
			ChallengeSet challengeSet;

			NamedPipe* writingPipe;
			NamedPipe* readingPipe;
			SVCPacketReader* packetReader;
			MutexedQueue<SVCPacket*>* incomingQueue;
			SVCPacketHandler* packetHandler;
			MutexedQueue<SVCPacket*>* dataHoldQueue;
			static void incoming_packet_handler(SVCPacket* packet, void* args);
		
			SVCEndpoint(SVC* svc, bool isInitiator, NamedPipe* readPipe, uint64_t pipeID);
			void stopWorking(bool isInitiator);

		public:
			~SVCEndpoint();
			bool negotiate(int timeout);
			ssize_t write(const uint8_t* buffer, uint16_t bufferLen, uint8_t option);
			ssize_t read(uint8_t* buffer, uint16_t bufferLen, uint8_t option);
			void shutdown();
	};
	
	class SVC{
		friend class SVCEndpoint;

		private:
			uint32_t appID;
			uint64_t pipeID;
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
			
		public:
			SVC(const std::string& appIdentity, SVCAuthenticator* authenticator);
			~SVC();
			void shutdown();
			SVCEndpoint* establishConnection(const std::string& remoteHost, uint8_t option);
			SVCEndpoint* listenConnection(const std::string& remoteHost, uint8_t option);
	};
	
#endif
