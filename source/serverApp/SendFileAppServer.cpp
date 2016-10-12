#include "../src/svc/SVC.h"
#include "../src/svc/host/SVCHostIP.h"
#include "../src/svc/authenticator/SVCAuthenticatorSimple.h"

//--TODO: to be remove debugging headers
#include <iostream>

using namespace std;

int main(int argc, char** argv){

	string appID = string("SEND_FILE_APP");	
	SVCAuthenticatorSharedSecret authenticator = new SVCAuthenticatorSharedSecret("./private/sharedsecret");
	
	SVC svc = new SVC(appID, authenticator);	
	SVCEndPoint endPoint = svc->listenConnection();
	
	if (endPoint!=NULL){
		printf("\nConnection established!");
	}
	else{
		printf("\nCannot establish connection!");
	}
	
	delete endPoint;
	delete svc;
}
