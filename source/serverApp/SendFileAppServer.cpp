#include "../src/svc/SVC.h"
#include "../src/svc/host/SVCHostIP.h"
#include "../src/svc/authenticator/SVCAuthenticatorSharedSecret.h"

using namespace std;

int main(int argc, char** argv){

	string appID = string("SEND_FILE_APP");	
	SVCAuthenticatorSharedSecret* authenticator = new SVCAuthenticatorSharedSecret("./private/sharedsecret");
	
	try{
		SVC* svc = new SVC(appID, authenticator);		
		SVCEndpoint* endpoint = svc->listenConnection(-1);
	
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
}
