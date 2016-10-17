#include "SVC.h"

//---for debugging, to be removed
#include <iostream>
#include <errno.h>

//--	SVC IMPLEMENTATION	--//

uint16_t SVC::endpointCounter = 0;

SVC::SVC(string appID, SVCAuthenticator* authenticator){
	
	const char* errorString;
	this->sha256 = new SHA256();

	struct sockaddr_un appSockAddr;
	struct sockaddr_un dmnSockAddr;	
	
	//--	copy param
	this->authenticator = authenticator;
	
	//--	check if the app is running
	string appIDHashed = this->sha256->hash(appID);
	this->appID = *((uint32_t*)appIDHashed.c_str()); //-- extract first 32 bits of hash string
	this->appSockPath = SVC_CLIENT_PATH_PREFIX + appIDHashed;
	unlink(this->appSockPath.c_str());				//-- try to remove the file in case of leftover by dead instance	
	if (unlink(this->appSockPath.c_str())==0){ 		//-- then try again to make sure that the app is currently running
		errorString = SVC_ERROR_NAME_EXISTED;
		goto errorInit;
	}
	//printf("\nappIDHashed: %s", appIDHashed.c_str());
	//printf("\nappID: %02x: ", this->appID);
	
	//--	bind app socket
	this->appSocket = socket(AF_LOCAL, SOCK_DGRAM, 0);
	memset(&appSockAddr, 0, sizeof(appSockAddr));
	appSockAddr.sun_family = AF_LOCAL;
	memcpy(appSockAddr.sun_path, appSockPath.c_str(), this->appSockPath.size());
	if (bind(this->appSocket, (struct sockaddr*)&appSockAddr, sizeof(appSockAddr))==-1){
		errorString = SVC_ERROR_BINDING;
		goto errorInit;
	}
	
	//--	connect to daemon socket
	memset(&dmnSockAddr, 0, sizeof(dmnSockAddr));
	dmnSockAddr.sun_family = AF_LOCAL;
	memcpy(dmnSockAddr.sun_path, SVC_DAEMON_PATH.c_str(), SVC_DAEMON_PATH.size());
	connect(this->appSocket, (struct sockaddr*) &dmnSockAddr, sizeof(dmnSockAddr));
	
	//--	init variables
	this->connectionRequests = new MutexedQueue<Message*>();
	//this->endPointsMutex = new SharedMutex();
	
	//--	BLOCK ALL KIND OF SIGNAL
	sigset_t sig;
	sigfillset(&sig);
	
	if (pthread_sigmask(SIG_BLOCK, &sig, NULL)!=0){
		errorString = SVC_ERROR_CRITICAL;
		goto errorInit;
	}
	
	//--	handler for data and command
	this->packetHandler = new PacketHandler(this->appSocket);
	
	goto success;
	
	//-- label
	errorInit:	
		this->shutdown();
		throw errorString;
	success:
		printf("\nsvc created");
	
}

void SVC::shutdown(){
	
	//unlink(this->appSockPath.c_str());
	//delete this->packetHandler;
	//delete this->sha256;
	
	printf("\nsvc destructed");
}


SVC::~SVC(){
	this->shutdown();
}

//--	SVC PUBLIC FUNCTION IMPLEMENTATION		--//

SVCEndpoint* SVC::establishConnection(SVCHost* remoteHost){
	
	//-- create new endpoint to handle further packets
	SVCEndpoint* endpoint = new SVCEndpoint(this->appID);
	//-- add this endpoint to be handled
	this->endpoints[endpoint->endpointID] = endpoint;
	
	//-- send SVC_CMD_CREATE_ENDPOINT to daemon
	uint8_t* packet = createSVCPacket(12); //-- 2 + (2 + 8)
	packet[SVC_PACKET_HEADER_LEN] = SVC_CMD_CREATE_ENDPOINT;
	addPacketParam(packet, (uint8_t*)&(endpoint->endpointID), ENDPOINTID_LENGTH);
	this->packetHandler->sendPacket(packet, SVC_PACKET_HEADER_LEN + 12);
	
	//-- wait for response from daemon endpoint then connect the app endpoint socket to daemon endpoint address
	uint32_t responseLen;
	if (endpoint->packetHandler->waitCommand(SVC_CMD_CREATE_ENDPOINT, endpoint->endpointID, packet, &responseLen, -1)){
		endpoint->connectToDaemon();
		return endpoint;
	}
	else{
		//-- remove endpoint from the map
		this->endpoints[endpoint->endpointID] = NULL;
		delete endpoint;
		return NULL;
	}
	return NULL;
}

SVCEndpoint* SVC::listenConnection(int timeout, int* status){

}
//--	SVCENDPOINT class	//

SVCEndpoint::SVCEndpoint(uint32_t appID){
	
	//--	generate endpointID
	this->endpointID = 0;
	this->endpointID |= appID;
	this->endpointID <<=16;
	this->endpointID |= SVC::endpointCounter;
	this->endpointID <<=16;
	
	//--	create a socket for listening to data
	//-- bind app endpoint socket
	this->sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	string endpointSockPath = SVC_ENDPOINT_APP_PATH_PREFIX + to_string(this->endpointID);	
	struct sockaddr_un sockAddr;
	memset(&sockAddr, 0, sizeof(sockAddr));
	sockAddr.sun_family = AF_LOCAL;
	memcpy(sockAddr.sun_path, endpointSockPath.c_str(), endpointSockPath.size());
	bind(this->sock, (struct sockaddr*)&sockAddr, sizeof(sockAddr));
	//-- create a packet handler to process incoming packets
	this->packetHandler = new PacketHandler(this->sock);
};

void SVCEndpoint::connectToDaemon(){
	string endpointDmnSockPath = SVC_ENDPOINT_DMN_PATH_PREFIX + to_string(this->endpointID);
	struct sockaddr_un dmnEndpointAddr;
	memset(&dmnEndpointAddr, 0, sizeof(dmnEndpointAddr));
	dmnEndpointAddr.sun_family = AF_LOCAL;
	memcpy(dmnEndpointAddr.sun_path, endpointDmnSockPath.c_str(), endpointDmnSockPath.size());
	connect(this->sock, (struct sockaddr*)&dmnEndpointAddr, sizeof(dmnEndpointAddr));
}

SVCEndpoint::~SVCEndpoint(){
	delete this->packetHandler;
}

int SVCEndpoint::sendData(const uint8_t* data, size_t dalalen, uint8_t priority, bool tcp){
	return 0;
}

int SVCEndpoint::readData(uint8_t* data, size_t* len){
	return 0;
}

