#ifndef __SVC_DAEMON_HEADER__
#define __SVC_DAEMON_HEADER__

	#include "SVC-utils.h"
	#include <cstdlib>
	#include <netinet/in.h>
	#include <unordered_map>
	#include <unistd.h>
	#include <sys/un.h>
	
	#define SVC_VERSION 0x01
	
	class DaemonEndpoint{
		private:
			//-- private members
			bool isAuthenticated;
			int dmnSocket;
			PacketHandler* packetHandler;
			
		public:
			//-- constructors/destructors
			DaemonEndpoint(uint64_t endpointID);
			~DaemonEndpoint();
			
			//-- public members
			uint64_t endpointID;
						
			//-- public methods
			void sendPacketToApp(const uint8_t* packet, uint32_t packetLen);
	};

	//---------------------------//
	
#endif
