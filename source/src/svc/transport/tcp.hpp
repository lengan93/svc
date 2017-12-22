#ifndef __TCP__
#define __TCP__

#include <sys/socket.h>
#include <arpa/inet.h>

#include "transport_handler.hpp"
#define TCP_UTM 1400

class TCP : public TransportHandler {
private :
	int sock;
    struct sockaddr_in me, other;
    socklen_t other_socklen = sizeof other;

public:
	TCP() {
		sock = socket(AF_INET , SOCK_STREAM , 0);
		if(sock == -1) throw "Could not create socket";
	}

	int sendData(uint8_t* data, uint32_t len) {
		if(send(sock, &len, 4, 0) != -1) {
			return send(sock, data, len, 0);
		}
		return -1;
	}

	int recvData(uint8_t* data, uint32_t* len) {
		int bytes = 0;
		recv(sock, len, 4, 0);
		
		for (int i = 0; i < *len; i += bytes) {
			if ((bytes = recv(sock, data +i, *len  - i, 0)) == -1) {
				printf("recv failed");
				return -1;
			}
		}
		
		// printf("%d\n", *len);
		return 0;
	}
	
	int connect_to(SVCHost* host) {
		other.sin_addr.s_addr = host->getHostAddress();
	    other.sin_family = AF_INET;
	    other.sin_port = htons( SVC_DEFAULT_PORT );

	 	if(connect(sock, (struct sockaddr *)&other, other_socklen) < 0) {
	 		printf("Could not connect to the remote\n");
	 		return -1;
	 	}
	 	return 0;
	}
	
	int listen(int port) {
		me.sin_addr.s_addr = INADDR_ANY;
	    me.sin_family = AF_INET;
	    me.sin_port = htons( port );
		if( bind(sock,(struct sockaddr *)&me , sizeof(me)) < 0)
	    {
	        //print the error message
	        perror("bind failed. Error");
	        return -1;
	    }

	    ::listen(sock, 3);

	    int tmp = accept(sock, (struct sockaddr *)&other, &other_socklen);
	    if(tmp < 0) {
	    	printf("accept failed!!\n");
	    	return -1;
	    }

	    sock = tmp;

	    return 0;
	}
};

#endif