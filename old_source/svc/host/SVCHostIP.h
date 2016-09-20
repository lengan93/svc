#ifndef __SCV_HOSTIP__
#define __SVC_HOSTIP__

	#include "SVCHost.h"
	#include <netinet/in.h>
	#include <arpa/inet.h>
	
	class SVCHostIP : public SVCHost {

		struct in_addr hostAddr;
		std::string ipAddress;

		public:
			SVCHostIP(std::string ipAddress);
			uint32_t getHostAddress();
	};

#endif
