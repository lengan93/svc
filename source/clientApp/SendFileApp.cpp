#include <iostream>

#include "../src/svc/SVC.h"
#include "../src/svc/host/SVCHostIP.h"
#include "../src/svc/authenticator/SVCAuthenticatorSharedSecret.h"


using namespace std;

int main(int argc, char** argv){
	
	string appID = string("SEND_FILE_APP");
	SVCHost* remoteHost = new SVCHostIP("149.56.142.13");
	SVCAuthenticatorSharedSecret* authenticator = new SVCAuthenticatorSharedSecret("./private/sharedsecret");
	
	try{
		SVC* svc = new SVC(appID, authenticator);		
		SVCEndpoint* endpoint = svc->establishConnection(remoteHost, 0);
		if (endpoint!=NULL){
			if (endpoint->negotiate()){
				string text;
				uint8_t buffer[SVC_DEFAULT_BUFSIZ]="";
				uint32_t dataLen;
				printf("\nConnection established.");
				do{
					printf("\nInput a text to be sent (input 'close' to terminate): ");
					cin>>text;
					endpoint->sendData((uint8_t*)text.c_str(), text.size());
					if (endpoint->readData(buffer, &dataLen, 1000) ==0){
						text = string((char*)buffer, dataLen);
						printf("Received echo: %s", text.c_str());
					}
				}
				while (text != "close" && endpoint->isAlive());
				endpoint->shutdownEndpoint();
				printf("\nProgram terminated.\n");
			}
			else{
				printf("\nCannot establish connection. Program terminated.\n");
			}
			delete endpoint;
		}
		svc->shutdownSVC();
		delete svc;		
	}
	catch (const char* str){
		printf("\nError: %s\n", str);
	}
		
	delete authenticator;
	delete remoteHost;
		
}
