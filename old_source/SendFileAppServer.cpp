#include "SendFileAppServer.h"

//--TODO:	to be removed

using namespace std;

SVC* svcInstance;

int main(int argc, char** argv){
	   
	working = true;
	SendFileAppServer* app = new SendFileAppServer();
	
	delete app;
}

SendFileAppServer::SendFileAppServer(){		
	svcInstance = new SVC(this, this);
	SVCEndPoint* endPoint;
		
	printf("Listening for incoming connection...");
	endPoint = svcInstance->listenConnection();
	if (endPoint!=NULL){
		printf("\nclient connected");		
	}
	else{
		printf("\nConnection attempt failed");
	}
}

SendFileAppServer::~SendFileAppServer(){
	delete svcInstance;
}

//interface implementation

//--	SVCApp interface

string SendFileAppServer::getAppID(){
	return string("SEND_FILE_APP");
}

/*	SVCAuthenticator interface	*/

string SendFileAppServer::getIdentity(){
	return "IM_THE_SERVER";
}

bool SendFileAppServer::verifyIdentity(string identity, string challenge, string proof){
	return (identity.compare("IM_THE_CLIENT")==0 && challenge.append("OK").compare(proof)==0);
}

string SendFileAppServer::generateProof(string challenge){
	return challenge.append("OK");
}

string SendFileAppServer::generateChallenge(){
	return string("this can be another thing");
}
