#ifndef __SCV_HOSTIP__
#define __SVC_HOSTIP__

	#include "SVCHost.h"
	#include <netinet/in.h>
	#include <arpa/inet.h>
	
	#define STR_INVALID_IP_ADDR "Invalid IP address"
	
	class SVCHostIP : public SVCHost {

		struct in_addr hostAddr;
		std::string ipAddress;
		std::string appID;

		public:
			SVCHostIP(std::string appID, std::string ipAddress);
			uint32_t getHostAddress();
			std::string getAppID();
	};
	
	SVCHostIP::SVCHostIP(std::string appID, std::string ipAddress){
		this->ipAddress = ipAddress;
		this->appID = appID;
		int result = inet_aton(ipAddress.c_str(), &(this->hostAddr));
		if (result == -1)
			throw STR_INVALID_IP_ADDR;		
	}

	uint32_t SVCHostIP::getHostAddress(){
		return (uint32_t)(this->hostAddr.s_addr);
	}

	std::string SVCHostIP::getAppID(){
		return this->appID;
	}

#endif
