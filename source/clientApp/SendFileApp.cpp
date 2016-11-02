#include "../src/svc/SVC.h"
#include "../src/svc/host/SVCHostIP.h"
#include "../src/svc/authenticator/SVCAuthenticatorSharedSecret.h"


using namespace std;

int main(int argc, char** argv){
	
	string appID = string("SEND_FILE_APP");
	SVCHost* remoteHost = new SVCHostIP("149.56.142.13");
	SVCAuthenticatorSharedSecret* authenticator = new SVCAuthenticatorSharedSecret("./private/sharedsecret");
	
	SVC* svc = NULL;
	
	try{
		svc = new SVC(appID, authenticator);
		
		SVCEndpoint* endpoint = svc->establishConnection(remoteHost);
		if (endpoint!=NULL){
			if (endpoint->negotiate()){
				printf("\nConnection established!");
				//-- try to send some data
				string someData = string("hello server!!!!");
				endpoint->sendData((uint8_t*)someData.c_str(), someData.size(), SVC_URGENT_PRIORITY, false);
			}
			else{
				printf("\nCannot establish connection!");
			}
			delete endpoint;
		}		
		delete svc;
	}
	catch (const char* str){
		printf("\nError: %s\n", str);
	}
	
	delete authenticator;
	delete remoteHost;
		
}
