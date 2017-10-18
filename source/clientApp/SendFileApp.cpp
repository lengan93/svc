#include <iostream>
#include <time.h>

#include "../src/svc/SVC.h"
#include "../src/svc/host/SVCHostIP.h"
#include "../src/svc/authenticator/SVCAuthenticatorSharedSecret.h"

using namespace std;

class Connector
{
private:
	int type;
	SVCAuthenticatorSharedSecret* authenticator = NULL;
	SVC* svc = NULL;
	SVCEndpoint* endpoint = NULL;

	int udpsock;
	struct sockaddr_in server;
	int server_size;
public:
	Connector(){}
	static Connector* get_SVC_connector(char* host_addr) {
		
		Connector* con = new Connector();
		con->type = SVC_CONNECTOR;

		SVCHost* remoteHost;
	
		string appID = string("CAMERA_APP");
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

	int readData(uint8_t* data, uint32_t* len);

	~Connector();
	
};

int GetFileSize(std::string filename){
    ifstream file(filename.c_str(), ios::binary | ios::ate);
	return file.tellg();
}

float timeDistance(const struct timespec* greater, const struct timespec* smaller){
	float sec = greater->tv_sec - smaller->tv_sec;
	float nsec;
	if (greater->tv_nsec < smaller->tv_nsec){
		sec -= 1;
		nsec = greater->tv_nsec + 1000000000 - smaller->tv_nsec;
	}
	else{
		nsec = greater->tv_nsec - smaller->tv_nsec;
	}
	nsec /= 1000000000;
	sec += nsec;
	return sec;
}

int main(int argc, char** argv){

	int RETRY_TIME = atoi(argv[2]);
	// int counter = 0;

	if (argc>1){
		string appID = string("SEND_FILE_APP");
		string hostAddr = "192.168.43.149";
		if(argc > 3) {
			hostAddr = argv[3];
		}
		// SVCHost* remoteHost = new SVCHostIP("149.56.142.13");
		SVCHost* remoteHost = new SVCHostIP(hostAddr);
		
		SVCAuthenticatorSharedSecret* authenticator = new SVCAuthenticatorSharedSecret("./private/sharedsecret");
	
		try{
			SVC* svc = new SVC(appID, authenticator);
			struct timespec startingTime;
			struct timespec echelon;
			clock_gettime(CLOCK_REALTIME, &startingTime);
			
			SVCEndpoint* endpoint = svc->establishConnection(remoteHost, 0);
			if (endpoint!=NULL){
				if (endpoint->negotiate()){
					clock_gettime(CLOCK_REALTIME, &echelon);
					printf("\n[%0.2f] Connection established.", timeDistance(&echelon, &startingTime)); fflush(stdout);
					
					uint32_t bufferSize = 1300;
					uint8_t buffer[bufferSize+1] = "";
										
					//-- send the file throw this connection
					string fileName = string(argv[1]);
					int fileSize = GetFileSize(fileName);
					if (fileSize >=0){
						printf("\nSending file: %s, size: %d", fileName.c_str(), fileSize); fflush(stdout);						
										
						//-- firstly send the file description, 4 byte filesize, then the rest will be fileName
						buffer[0]=0x01;
						memcpy(buffer+1, &fileSize, 4);
						memcpy(buffer+1+4, (uint8_t*)fileName.c_str(), fileName.size());
						for (int i=0;i<RETRY_TIME;i++){
							endpoint->sendData(buffer, 1+4+fileName.size());
							// counter++;
						}						
				
						//-- then send the content
						if (fileSize>0){
							ifstream bigFile(argv[1]);
							int blocsize;
							buffer[0] = 0x02;
							while (bigFile && endpoint->isAlive()){
								blocsize = bufferSize;
								bigFile.read((char*)buffer+1, blocsize);
								if(bigFile.eof()) {
									blocsize = bigFile.gcount();
								}

								endpoint->sendData(buffer, blocsize+1);
								// counter++;
							}													
							bigFile.close();
						}
						
						//-- then send terminating packets
						buffer[0] = 0x03;
						for (int i=0;i<RETRY_TIME;i++){
							endpoint->sendData(buffer, 1);
							// counter++;
						}
						buffer[0] = 0x00;
						
						//-- read to check that server send terminating signal
						clock_gettime(CLOCK_REALTIME, &echelon);
						printf("\n[%0.2f] All data sent, waiting ACK", timeDistance(&echelon, &startingTime)); fflush(stdout);
						// printf("\n%d packets sent", counter); fflush(stdout);
						bool fileSent = false;
						do{
							if (endpoint->readData(buffer, &bufferSize, 1000) == 0){
								if (buffer[0] = 0x03 && buffer[1]==0xFF){
									fileSent = true;																		
								}
							}
						}
						while (!fileSent);
						
						clock_gettime(CLOCK_REALTIME, &echelon);
						float totalTime = timeDistance(&echelon, &startingTime);
						printf("\n[%0.2f] File sent, average speed: %0.0f KB/s", totalTime, fileSize/totalTime/1024); fflush(stdout);
					}
					else{
						printf("\nFile not valid\n");
					}										
				}
				else{
					printf("\nCannot establish connection. Program terminated.\n");
				}
				delete endpoint;
			}
			svc->shutdownSVC();
			delete svc;
			
			clock_gettime(CLOCK_REALTIME, &echelon);
			printf("\n[%0.2f] Program terminated\n", timeDistance(&echelon, &startingTime)); fflush(stdout);
		}
		catch (const char* str){
			printf("\nError: %s\n", str);
		}
		
		delete authenticator;
		delete remoteHost;
	}
		
}
