
#include "connector.h"

int Connector::GetFileSize(std::string filename){
    ifstream file(filename.c_str(), ios::binary | ios::ate);
	return file.tellg();
}

float Connector::timeDistance(const struct timespec* greater, const struct timespec* smaller){
	float sec = greater->tv_sec - smaller->tv_sec;
	float nsec;
	if (greater->tv_nsec < smaller->tv_nsec){
		sec -= 1;
		nsec = greater->tv_nsec + 1000000000 - smaller->tv_nsec;
	}
	else{
		nsec = greater->tv_nsec - smaller->tv_nsec;
	}
	nsec /= 1000000000;
	sec += nsec;
	return sec;
}

Connector::Connector(std::string remoteHost) {
	this->remoteHost = remoteHost;


	this->appID = "anAppID";
	this->authenticator = new SVCAuthenticatorSharedSecret("./private/sharedsecret");
	this->endpoint;
}

Connector::Connector(std::string appID, std::string remoteHost, SVCAuthenticatorSharedSecret* authenticator);

Connector::~Connector();

int Connector::sendFile(std::string filename);