#include "../src/svc/SVC.h"
#include "../src/svc/host/SVCHostIP.h"
#include "../src/svc/authenticator/SVCAuthenticatorSharedSecret.h"


using namespace std;

int main(int argc, char** argv){

	string appID = string("SEND_FILE_APP");
	SVCHost* remoteHost = new SVCHostIP("149.56.142.13");
	SVCAuthenticatorSharedSecret* authenticator = new SVCAuthenticatorSharedSecret("./private/sharedsecret");
	
	SVC* svc = new SVC(appID, authenticator);	
	SVCEndpoint* endpoint = svc->establishConnection(remoteHost);
	
	if (endpoint!=NULL){
		printf("\nConnection established!");
	}
	else{
		printf("\nCannot establish connection!");
	}
	
	delete endpoint;
	delete svc;
	delete authenticator;
		
}
