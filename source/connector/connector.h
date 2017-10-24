/* Secure Virtual Connector (SVC) API header */

#ifndef __CONNECTOR__
#define __CONNECTOR__

#include "../src/svc/SVC.h"
#include "../src/svc/host/SVCHostIP.h"
#include "../src/svc/authenticator/SVCAuthenticatorSharedSecret.h"


#define SVC_CONNECTOR 0
#define UDP_CONNECTOR 1

class Connector
{
private:
	int type;
	SVCAuthenticatorSharedSecret* authenticator = NULL;
	SVC* svc = NULL;
	SVCEndpoint* endpoint = NULL;

	int udpsock;
	struct sockaddr_in server;
	socklen_t server_size;
public:
	Connector(){}
	static Connector* get_SVC_connector(char* host_addr) {
		
		Connector* con = new Connector();
		con->type = SVC_CONNECTOR;

		SVCHost* remoteHost;
	
		string appID = string("SEND_FILE_APP");
		remoteHost = new SVCHostIP(host_addr);

		con->authenticator = new SVCAuthenticatorSharedSecret("./private/sharedsecret");

		con->svc = new SVC(appID, con->authenticator);
		
		con->endpoint = con->svc->establishConnection(remoteHost, 0);
		if (con->endpoint!=NULL){
			if (con->endpoint->negotiate()){
				printf("Connection established.\n");
				return con;
			}
		}
		return NULL;
	}

	static Connector* get_UDP_connector(char* host_addr){
		
		Connector* con = new Connector();
	    con->type = UDP_CONNECTOR;
	    //Create socket
	    con->udpsock = socket(AF_INET , SOCK_DGRAM , 0);
	    if (con->udpsock == -1)
	    {
	        printf("Could not create socket");
	        return NULL;
	    }
	     
	    con->server.sin_addr.s_addr = inet_addr(host_addr);
	    // server.sin_addr.s_addr = inet_addr("127.0.0.1");
	    con->server.sin_family = AF_INET;
	    int serverport = 8888;
	    con->server.sin_port = htons( serverport );
	 	
	 	con->server_size = sizeof con->server;

	 	return con;
	}

	static Connector* get_SVC_server_connector(){
		Connector* con = new Connector();
		con->type = SVC_CONNECTOR;

	
		string appID = string("SEND_FILE_APP");

		con->authenticator = new SVCAuthenticatorSharedSecret("./private/sharedsecret");

		con->svc = new SVC(appID, con->authenticator);
		
		con->endpoint = con->svc->listenConnection(SVC_DEFAULT_TIMEOUT);
		if (con->endpoint!=NULL){
			if (con->endpoint->negotiate()){
				printf("Connection established.\n");
				return con;
			}
		}
		return NULL;
	}

	static Connector* get_UDP_server_connector(){
		
		Connector* con = new Connector();
	    con->type = UDP_CONNECTOR;
	    //Create socket
	    con->udpsock = socket(AF_INET , SOCK_DGRAM , 0);
	    if (con->udpsock == -1)
	    {
	        printf("Could not create socket");
	        return NULL;
	    }
	     
	    con->server.sin_addr.s_addr = INADDR_ANY;
	    // server.sin_addr.s_addr = inet_addr("127.0.0.1");
	    con->server.sin_family = AF_INET;
	    int serverport = 8888;
	    con->server.sin_port = htons( serverport );
	 	
	 	con->server_size = sizeof con->server;

	 	if( bind(con->udpsock,(struct sockaddr *)&con->server , con->server_size) < 0)
	    {
	        //print the error message
	        printf("bind failed. Error");
	        return NULL;
	    }

	 	return con;
	}

	int sendData(uint8_t* data, uint32_t len) {
		switch(type) {
			case SVC_CONNECTOR:
				if(endpoint == NULL) {
					return -1;
				}
				return endpoint->sendData(data, len);
			case UDP_CONNECTOR:
				// cout << inet_ntoa(server.sin_addr) <<" " <<ntohs(server.sin_port)<<endl;
				// printBuffer(data, len);
				return sendto(udpsock, data, len, 0, (sockaddr *)&server, server_size);
			default:
				return -1;
		}
	}

	int readData(uint8_t* data, uint32_t* len) {
		switch(this->type) {
			case SVC_CONNECTOR :
				if(endpoint == NULL) {
					return -1;
				}
				return endpoint->readData(data, len, -1);
			case UDP_CONNECTOR:
				// printf("before recvfrom\n");
				*len = recvfrom(udpsock, data, 6000, 0, (sockaddr*) &server, &server_size);
				// printf("after recvfrom\n");
				return 0;
		}
	}

	~Connector();
	
};

#endif
