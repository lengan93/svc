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
public:
	
	virtual int sendData(uint8_t* data, uint32_t len) = 0; 

	virtual int readData(uint8_t* data, uint32_t* len) = 0;

};

class SVC_Connector : public Connector
{
private:
	SVCAuthenticatorSharedSecret* authenticator = NULL;
	SVC* svc = NULL;
	SVCEndpoint* endpoint = NULL;
public:
	
	SVC_Connector(){}

	static Connector* get_client_instance(char* host_addr) {
		
		SVC_Connector* con = new SVC_Connector();

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

	static Connector* get_server_instance(){
		SVC_Connector* con = new SVC_Connector();
	
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

	int sendData(uint8_t* data, uint32_t len) {
		if(endpoint == NULL) {
			return -1;
		}
		return endpoint->sendData(data, len);
	}

	int readData(uint8_t* data, uint32_t* len) {
		if(endpoint == NULL) {
			return -1;
		}
		return endpoint->readData(data, len, -1);
	}

	~SVC_Connector();
	
};

class UDP_Connector : public Connector
{
private:	
	int udpsock;
	struct sockaddr_in remote;
	socklen_t remote_size;

public:
	UDP_Connector() {}

	static Connector* get_client_instance(char* host_addr){
		
		UDP_Connector* con = new UDP_Connector();
	    //Create socket
	    con->udpsock = socket(AF_INET , SOCK_DGRAM , 0);
	    if (con->udpsock == -1)
	    {
	        printf("Could not create socket");
	        return NULL;
	    }
	     
	    con->remote.sin_addr.s_addr = inet_addr(host_addr);
	    // server.sin_addr.s_addr = inet_addr("127.0.0.1");
	    con->remote.sin_family = AF_INET;
	    int serverport = 8888;
	    con->remote.sin_port = htons( serverport );
	 	
	 	con->remote_size = sizeof con->remote;

	 	return con;
	}

	static Connector* get_server_instance(){
		UDP_Connector* con = new UDP_Connector();
	    //Create socket
	    con->udpsock = socket(AF_INET , SOCK_DGRAM , 0);
	    if (con->udpsock == -1)
	    {
	        printf("Could not create socket");
	        return NULL;
	    }
	     
	    con->remote.sin_addr.s_addr = INADDR_ANY;
	    // server.sin_addr.s_addr = inet_addr("127.0.0.1");
	    con->remote.sin_family = AF_INET;
	    int serverport = 8888;
	    con->remote.sin_port = htons( serverport );
	 	
	 	con->remote_size = sizeof con->remote;

	 	if( bind(con->udpsock,(struct sockaddr *)&con->remote , con->remote_size) < 0)
	    {
	        //print the error message
	        printf("bind failed. Error");
	        return NULL;
	    }

	 	return con;
	}

	int sendData(uint8_t* data, uint32_t len) {
		return sendto(udpsock, data, len, 0, (sockaddr *)&remote, remote_size);
	}

	int readData(uint8_t* data, uint32_t* len) {
		*len = recvfrom(udpsock, data, 6000, 0, (sockaddr*) &remote, &remote_size);
		return 0;
	}

	~UDP_Connector();
	
};

class TCP_Connector : public Connector
{
private:	
	int tcpsock;
	struct sockaddr_in remote;
	socklen_t remote_size;

public:
	TCP_Connector() {}

	static Connector* get_client_instance(char* host_addr){
		
		TCP_Connector* con = new TCP_Connector();
	    //Create socket
	    con->tcpsock = socket(AF_INET , SOCK_STREAM , 0);
	    if (con->tcpsock == -1)
	    {
	        printf("Could not create socket");
	        return NULL;
	    }
	     
	    con->remote.sin_addr.s_addr = inet_addr(host_addr);
	    // server.sin_addr.s_addr = inet_addr("127.0.0.1");
	    con->remote.sin_family = AF_INET;
	    int serverport = 8888;
	    con->remote.sin_port = htons( serverport );
	 	
	 	con->remote_size = sizeof con->remote;

	 	if(connect(con->tcpsock, (struct sockaddr *)&con->remote, con->remote_size) < 0) {
	 		printf("Could not connect to the remote\n");
	 		return NULL;
	 	}

	 	return con;
	}

	static Connector* get_server_instance(){
		TCP_Connector* con = new TCP_Connector();
	    //Create socket
	    int sock = socket(AF_INET , SOCK_STREAM , 0);
	    if (sock == -1)
	    {
	        printf("Could not create socket");
	        return NULL;
	    }
	     
	    con->remote.sin_addr.s_addr = INADDR_ANY;
	    // server.sin_addr.s_addr = inet_addr("127.0.0.1");
	    con->remote.sin_family = AF_INET;
	    int serverport = 8888;
	    con->remote.sin_port = htons( serverport );
	 	
	 	con->remote_size = sizeof con->remote;

	 	if( bind(sock,(struct sockaddr *)&con->remote , con->remote_size) < 0)
	    {
	        //print the error message
	        printf("bind failed. Error");
	        return NULL;
	    }

	    listen(sock, 3);

	    con->tcpsock = accept(sock, (struct sockaddr *)&con->remote, &con->remote_size);
	    if(con->tcpsock < 0) {
	    	printf("accept failed!!\n");
	    	return NULL;
	    }

	 	return con;
	}

	int sendData(uint8_t* data, uint32_t len) {
		return send(tcpsock, data, len, 0);
	}

	int readData(uint8_t* data, uint32_t* len) {
		*len = recv(tcpsock, data, 6000, 0);
		return 0;
	}

	~TCP_Connector();
	
};

#endif
