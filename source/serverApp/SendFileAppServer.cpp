#include <iostream>

#include "../src/utils/PeriodicWorker.h"
#include "../src/svc/SVC.h"
#include "../src/svc/host/SVCHostIP.h"
#include "../src/svc/authenticator/SVCAuthenticatorSharedSecret.h"

using namespace std;

void sendBeatToClient(void* args){
	static uint8_t* beat = (uint8_t*)"server beat";
	SVCEndpoint* ep = (SVCEndpoint*)args;
	ep->sendData(beat, 12);
}

int main(int argc, char** argv){

	string appID = string("SEND_FILE_APP");	
	SVCAuthenticatorSharedSecret* authenticator = new SVCAuthenticatorSharedSecret("./private/sharedsecret");
	
	try{
		SVC* svc = new SVC(appID, authenticator);		
		printf("\nserver is listenning..."); fflush(stdout);
		SVCEndpoint* endpoint = svc->listenConnection(SVC_DEFAULT_TIMEOUT);
		if (endpoint!=NULL){
			if (endpoint->negotiate()){
				printf("\nConnection established!");
				//PeriodicWorker* pw = new PeriodicWorker(1000, sendBeatToClient, endpoint);
				//-- try to read some data
				uint8_t buffer[SVC_DEFAULT_BUFSIZ]="";
				uint32_t dataLen;
				string text;
				while (endpoint->isAlive()){
					if (endpoint->readData(buffer, &dataLen, 1000) == 0){
						text = string((char*)buffer, dataLen);
						printf("\nReceived: %s", text.c_str()); fflush(stdout);
						//-- send echo packet to client
						endpoint->sendData(buffer, dataLen);
					}
					//else{
					//	printf("\nread failed"); fflush(stdout);
					//}
				}
				//pw->stopWorking();
				//pw->waitStop();
				//delete pw;
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
