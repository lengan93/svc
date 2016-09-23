#include "SendFileApp.h"

//--TODO: to be remove debugging headers
#include <iostream>

using namespace std;

int main(int argc, char** argv){

	//--	read and extract IP from argv
	try{
		SendFileApp* app = new SendFileApp();
		printf("\napp initiated!");
	}
	catch(const char* err){
		cout<<err<<endl;
	}	
	//--	read file path from argv
	
	//--	perfrom send file
	
}

SendFileApp::SendFileApp(){
	
	string appID = string("SEND_FILE_APP");
	SVCHost* remoteHost = new SVCHostIP("149.56.142.13");
	
	this->svc = new SVC(appID, this);
	this->endPoint = this->svc->establishConnection(remoteHost);
	if (this->endPoint==NULL){
		svc->~SVC();
		throw "Error establishing connection";
	}
	
	printf("\nconnection established!");
}

SendFileApp::~SendFileApp(){
	delete this->endPoint;
	delete this->svc;
}

//--	interface implementation

string SendFileApp::getIdentity(){
	return "IM_THE_CLIENT";
}

bool SendFileApp::verifyIdentity(string identity, string challenge, string proof){
	return (identity.compare("IM_THE_SERVER")==0 && challenge.append("OK").compare(proof)==0);
}

string SendFileApp::generateProof(string challenge){
	return challenge.append("OK");
}

string SendFileApp::generateChallenge(){
	return string("this can be anything");
}
