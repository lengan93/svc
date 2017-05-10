#ifndef __HTP_SOCKADDR_H__
#define __HTP_SOCKADDR_H__

#include "Htp-header.h"

class HtpSockaddr{
	private:
		struct sockaddr_storage sockaddr;
		socklen_t addrLen;
	public:
		HtpSockaddr() {
			this->addrLen = sizeof(this->sockaddr);
			memset(&this->sockaddr, 0, this->addrLen);			
		}

		HtpSockaddr(const struct sockaddr_storage* sockaddr, socklen_t addrLen) {
			memset(&this->sockaddr, 0, sizeof(this->sockaddr));
			memcpy(&this->sockaddr, sockaddr, addrLen);
			this->addrLen = addrLen;
		}

		struct sockaddr_storage* getSockaddr() {
			return &sockaddr;
		}

		socklen_t getAddrlen() {
			return addrLen;
		}
}

#endif