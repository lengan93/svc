#include "../src/svc/SVC.h"
#include "../src/svc/host/SVCHostIP.h"
#include "../src/svc/authenticator/SVCAuthenticatorSharedSecret.h"

using namespace std;

int main(int argc, char** argv){

	string appID = string("SEND_FILE_APP");	
	SVCAuthenticatorSharedSecret* authenticator = new SVCAuthenticatorSharedSecret("./private/sharedsecret");
	
	try{
		SVC* svc = new SVC(appID, authenticator);	
		int status;
		SVCEndpoint* endpoint = svc->listenConnection(3000, &status);
	
		if (endpoint!=NULL){
			printf("\nConnection established!");
			delete endpoint;
		}
		else{
			printf("\nCannot establish connection!");
		}
		delete svc;
	}
	catch (...){
		printf("\nError: cannot create an instance of SVC\n");
	}
	
	delete authenticator;
}
