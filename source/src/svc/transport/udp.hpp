#ifndef __UDP__
#define __UDP__

#include <sys/socket.h>
#include <arpa/inet.h>

#include "transport_handler.hpp"

class UDP : public TransportHandler {
private :
	int sock;
    struct sockaddr_in me, other;
    socklen_t other_socken = sizeof other;

public:
	UDP() {
		sock = socket(AF_INET , SOCK_DGRAM , 0);
	}

	int sendData(uint8_t* data, int len) {
		return sendto(sock, data, len, 0, (sockaddr *)&other, other_socken);
	}

	int recvData(uint8_t* data, int len) {
		return recvfrom(sock, data, len, 0, (sockaddr *)&other, &other_socken);
	}
	
	int connect_to(SVCHost* host) {
		other.sin_addr.s_addr = host->getHostAddress();
	    other.sin_family = AF_INET;
	    other.sin_port = htons( 9999 );
	    return 1;
	}
	
	int listen() {

	}
};

#endif