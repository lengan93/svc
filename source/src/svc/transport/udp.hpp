#ifndef __UDP__
#define __UDP__

#include <sys/socket.h>
#include <arpa/inet.h>

#include "transport_handler.hpp"
#define UDP_UTM 1400

class UDP : public TransportHandler {
private :
	int sock;
    struct sockaddr_in me, other;
    socklen_t other_socken = sizeof other;

public:
	UDP() {
		sock = socket(AF_INET , SOCK_DGRAM , 0);
	}

	int sendData(uint8_t* data, uint32_t len) {
		int r = sendto(sock, data, len, 0, (sockaddr *)&other, other_socken);
		// cout << "sent a packet to " << inet_ntoa(other.sin_addr) << ":" << ntohs(other.sin_port) <<endl;
		return r;
	}

	int recvData(uint8_t* data, uint32_t* len) {
		*len = recvfrom(sock, data, UDP_UTM, 0, (sockaddr *)&other, &other_socken);
		// cout << "received a packet from "  << inet_ntoa(other.sin_addr) << ":" << ntohs(other.sin_port) <<endl;
		// printBuffer(data,*len);
		return *len;
	}
	
	int connect_to(SVCHost* host) {
		other.sin_addr.s_addr = host->getHostAddress();
	    other.sin_family = AF_INET;
	    other.sin_port = htons( 9999 );
	    return 1;
	}
	
	int listen() {
		me.sin_addr.s_addr = INADDR_ANY;
	    me.sin_family = AF_INET;
	    me.sin_port = htons( 9999 );
		if( bind(sock,(struct sockaddr *)&me , sizeof(me)) < 0)
	    {
	        //print the error message
	        perror("bind failed. Error");
	        return -1;
	    }
	    return 0;
	}
};

#endif