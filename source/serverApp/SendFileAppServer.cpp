#include <iostream>

#include "../src/utils/_PeriodicWorker.h"
#include "../src/svc/SVC.h"
// #include "../src/svc/host/SVCHostIP.h"
#include "../src/svc/authenticator/SVCAuthenticatorSharedSecret.h"


using namespace std;

bool fileReceived = false;
bool headerReceived = false;
int fileSize;
int readSize = 0;
string fileName;

int GetFileSize(std::string filename){
    ifstream file(filename.c_str(), ios::binary | ios::ate);
	return file.tellg();
}

void send_server_beat(void* args){
	uint8_t buffer[1];
	SVCEndpoint* ep = (SVCEndpoint*)args;
	buffer[0] = 0xFF;
	ep->write(buffer, 1, 0);
	if (headerReceived &!fileReceived){
		printf("\rReceived: %d/%d", readSize, fileSize); fflush(stdout);
	}
}

int main(int argc, char** argv){

	int RETRY_TIME = atoi(argv[1]);

	string appID = string("SEND_FILE_APP_SERVER");	
	SVCAuthenticatorSharedSecret* authenticator = new SVCAuthenticatorSharedSecret("./private/sharedsecret");
	
	try{
		SVC* svc = new SVC(appID, authenticator);		
		printf("\nserver is listenning..."); fflush(stdout);
		SVCEndpoint* endpoint = svc->listenConnection("", 0);
		if (endpoint!=NULL){
			if (endpoint->negotiate(3000)){
				printf("\nConnection established!");
				
				//pw to sent beat
				PeriodicWorker* pw = new PeriodicWorker(1000, send_server_beat, endpoint);								
				
				uint16_t bufferSize = 1400;
				uint8_t buffer[bufferSize];
				
				//-- try to read file size and name from the first message				
				
				while (!fileReceived){
					if ((bufferSize = endpoint->read(buffer, 1400, 0)) > 0){
						switch (buffer[0]){
							case 0x01:
								if (!headerReceived){
									headerReceived = true;
									fileSize = *((int*)(buffer+1));
									fileName = string((char*)buffer+1+4, bufferSize-1-4);									
									readSize = 0;
									printf("\nReceiving file: %s, size: %d\n", fileName.c_str(), fileSize); fflush(stdout);
								}
								break;
								
							case 0x02:
								if (headerReceived){
									readSize+=bufferSize;
								}
								break;
								
							case 0x03:
								if (!fileReceived){
									fileReceived = true;
									if (fileSize>0){
										printf("\nFile received %d/%d bytes, lost rate: %0.2f%\n", readSize, fileSize, (1.0 - (float)(readSize)/fileSize)*100); fflush(stdout);
									}
									else{
										printf("\nEmpty file received");
									}
								}												
								//printf("\nsend back 0x03"); fflush(stdout);
								for (int i=0; i<RETRY_TIME; i++){
									buffer[1]=0xFF;						
									endpoint->write(buffer, 2, 0);
									//printf(".");
								}
								fflush(stdout);
								break;
								
							default:
								break;
						}
					}
				}
								
				pw->stopWorking();
				pw->waitStop();
				delete pw;
								
				endpoint->shutdown();			
				printf("\nProgram terminated!\n");
			}
			else{
				printf("\nCannot establish connection!\n");
			}
			delete endpoint;
		}
		svc->shutdown();
		delete svc;
	}
	catch (...){
		printf("\nError: cannot create an instance of SVC\n");
	}
	
	delete authenticator;
}
