#ifndef __SCV_HOSTIP__
#define __SVC_HOSTIP__

	#include "SVCHost.h"
	#include <netinet/in.h>
	#include <arpa/inet.h>
	
	#define STR_INVALID_IP_ADDR "Invalid IP address"
	
	class SVCHostIP : public SVCHost {

		struct in_addr hostAddr;
		std::string ipAddress;

		public:
			SVCHostIP(std::string ipAddress);
			uint32_t getHostAddress();
	};
	
	SVCHostIP::SVCHostIP(string ipAddress){
		this->ipAddress = ipAddress;
		int result = inet_aton(ipAddress.c_str(), &(this->hostAddr));
		if (result == -1)
			throw STR_INVALID_IP_ADDR;		
	}

	uint32_t SVCHostIP::getHostAddress(){
		return (uint32_t)(this->hostAddr.s_addr);
	}

#endif
