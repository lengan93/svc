#include "../src/svc/SVC.h"
#include "../src/svc/host/SVCHostIP.h"
#include "../src/svc/authenticator/SVCAuthenticatorSharedSecret.h"

using namespace std;

int main(int argc, char** argv){

	string appID = string("SEND_FILE_APP");	
	SVCAuthenticatorSharedSecret* authenticator = new SVCAuthenticatorSharedSecret("./private/sharedsecret");
	
	try{
		SVC* svc = new SVC(appID, authenticator);		
		printf("\nserver is listenning..."); fflush(stdout);
		SVCEndpoint* endpoint = svc->listenConnection(-1);
		if (endpoint!=NULL){
			if (endpoint->negotiate()){
				printf("\nConnection established!");
				//-- try to read some data
				uint8_t* buffer = (uint8_t*)malloc(SVC_DEFAULT_BUFSIZ);
				uint32_t dataLen;
				if (endpoint->readData(buffer, &dataLen) == 0){
					string receivedData = string((char*)buffer, dataLen);
					printf("\nreceived some data: %s", receivedData.c_str());
				}
				//else: interrupted
			}
			else{
				printf("\nCannot establish connection!");
			}
			delete endpoint;
		}
		delete svc;
	}
	catch (...){
		printf("\nError: cannot create an instance of SVC\n");
	}
	
	delete authenticator;
}
