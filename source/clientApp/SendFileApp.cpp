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
	delete remoteHost;
		
}
