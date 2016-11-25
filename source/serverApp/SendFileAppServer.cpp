#include <iostream>

#include "../src/utils/PeriodicWorker.h"
#include "../src/svc/SVC.h"
#include "../src/svc/host/SVCHostIP.h"
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
	static uint8_t buffer[1] = {0x00};
	SVCEndpoint* ep = (SVCEndpoint*)args;
	ep->sendData(buffer, 10);
	if (headerReceived &!fileReceived){
		printf("\rReceived: %d/%d", readSize, fileSize); fflush(stdout);
	}
}

int main(int argc, char** argv){

	const int RETRY_TIME = 5;

	string appID = string("SEND_FILE_APP");	
	SVCAuthenticatorSharedSecret* authenticator = new SVCAuthenticatorSharedSecret("./private/sharedsecret");
	
	try{
		SVC* svc = new SVC(appID, authenticator);		
		printf("\nserver is listenning..."); fflush(stdout);
		SVCEndpoint* endpoint = svc->listenConnection(SVC_DEFAULT_TIMEOUT);
		if (endpoint!=NULL){
			if (endpoint->negotiate()){
				printf("\nConnection established!");
				
				//pw to sent beat
				PeriodicWorker* pw = new PeriodicWorker(1000, send_server_beat, endpoint);								
				
				uint32_t bufferSize = 1400;
				uint8_t buffer[bufferSize];
				
				//-- try to read file size and name from the first message				
				
				while (!fileReceived){
					if (endpoint->readData(buffer, &bufferSize, 3000) == 0){
						switch (buffer[0]){
							case 0x01:
								if (!headerReceived){
									fileSize = *((int*)(buffer+1));
									fileName = string((char*)buffer+1+4, bufferSize-1-4);
									headerReceived = true;
									printf("\nReceiving file: %s, size: %d\n", fileName.c_str(), fileSize); fflush(stdout);
								}
								break;
								
							case 0x02:
								if (headerReceived){
									readSize+=bufferSize;
								}
								break;
								
							case 0x03:
								fileReceived = true;
								memcpy(buffer+1, &readSize, 4);
								for (int i=0; i<RETRY_TIME; i++){
									endpoint->sendData(buffer, 5);
								}							
								break;
								
							default:
								break;
						}
					}
				}
								
				pw->stopWorking();
				pw->waitStop();
				delete pw;
				
				if (fileReceived){
					printf("\nFile received.");
				}
				endpoint->shutdownEndpoint();			
				printf("\nProgram terminated!\n");
			}
			else{
				printf("\nCannot establish connection!\n");
			}
			delete endpoint;
		}
		svc->shutdownSVC();
		delete svc;
	}
	catch (...){
		printf("\nError: cannot create an instance of SVC\n");
	}
	
	delete authenticator;
}
