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
	uint8_t* appIDBin;
	stringToHex(appIDHashed.substr(0, 8), &appIDBin); //-- extract first 32 bits of hash string
	this->appID = *((uint32_t*)appIDBin);
	this->appSockPath = SVC_CLIENT_PATH_PREFIX + appIDHashed.substr(0,8);
	
	//--	bind app socket
	this->appSocket = socket(AF_LOCAL, SOCK_DGRAM, 0);
	memset(&appSockAddr, 0, sizeof(appSockAddr));
	appSockAddr.sun_family = AF_LOCAL;
	memcpy(appSockAddr.sun_path, appSockPath.c_str(), this->appSockPath.size());
	if (bind(this->appSocket, (struct sockaddr*)&appSockAddr, sizeof(appSockAddr))==-1){
		errorString = SVC_ERROR_BINDING;
		delete this->sha256;
		goto errorInit;
	}
	
	//--	connect to daemon socket
	memset(&dmnSockAddr, 0, sizeof(dmnSockAddr));
	dmnSockAddr.sun_family = AF_LOCAL;
	memcpy(dmnSockAddr.sun_path, SVC_DAEMON_PATH.c_str(), SVC_DAEMON_PATH.size());
	connect(this->appSocket, (struct sockaddr*) &dmnSockAddr, sizeof(dmnSockAddr));
	
	//--	init variables
	this->connectionRequests = new MutexedQueue<SVCPacket*>();
	
	//--	BLOCK ALL KIND OF SIGNAL
	sigset_t sig;
	sigfillset(&sig);
	
	if (pthread_sigmask(SIG_BLOCK, &sig, NULL)!=0){
		errorString = SVC_ERROR_CRITICAL;
		unlink(this->appSockPath.c_str());
		delete this->sha256;
		goto errorInit;
	}
	
	//--	handler for data and command
	this->packetHandler = new PacketHandler(this->appSocket);
	this->packetHandler->setCommandHandler(svc_command_packet_handler, this);
	
	goto success;
	
	//-- label
	errorInit:	
		printf("\nError: %s", errorString);
		throw errorString;
	success:
		printf("\nSVC created");
		fflush(stdout);
	
}

void SVC::shutdown(){
	unlink(this->appSockPath.c_str());
	delete this->packetHandler;
	delete this->sha256;
	printf("\nsvc destructed\n");
	fflush(stdout);
}


SVC::~SVC(){
	this->shutdown();
}

void SVC::svc_command_packet_handler(SVCPacket* packet, void* args){
	SVC* _this = (SVC*)args;
	printf("\nsvc app receive packet: "); printBuffer(packet->packet, packet->dataLen); fflush(stdout);
	enum SVCCommand cmd = (enum SVCCommand)packet->packet[SVC_PACKET_HEADER_LEN];
	switch(cmd){
		case SVC_CMD_CONNECT_INNER2:
			_this->connectionRequests->enqueue(packet);
			printf("\nconnection request received");
			break;
		default:
			//-- remove the packet
			delete packet;
			break;
	}
}

//--	SVC PUBLIC FUNCTION IMPLEMENTATION		--//

SVCEndpoint* SVC::establishConnection(SVCHost* remoteHost){
	
	//-- create new endpoint to handle further packets
	SVCEndpoint* endpoint = new SVCEndpoint(this, true);
	uint64_t endpointID = 0;	
	endpointID |= SVC::endpointCounter;
	endpointID<<=32;
	endpointID |= this->appID;
	endpoint->bindToEndpointID(endpointID);
	
	endpoint->setRemoteHost(remoteHost);
	//-- add this endpoint to be handled
	this->endpoints[endpoint->endpointID] = endpoint;
	
	//-- send SVC_CMD_CREATE_ENDPOINT to daemon
	SVCPacket* packet = new SVCPacket(endpoint->endpointID); //-- 2 = cmd + argc
	packet->setCommand(SVC_CMD_CREATE_ENDPOINT);
	int sendrs = this->packetHandler->sendPacket(packet);
	
	//-- wait for response from daemon endpoint then connect the app endpoint socket to daemon endpoint address
	uint32_t responseLen;
	printf("\nsendrs: %d, waiting for SVC_CREATE_ENDPOINT", sendrs);
	fflush(stdout);
	if (endpoint->packetHandler->waitCommand(SVC_CMD_CREATE_ENDPOINT, endpoint->endpointID, packet, SVC_DEFAULT_TIMEOUT)){
		endpoint->connectToDaemon();
		return endpoint;
	}
	else{
		//-- remove endpoint from the map
		this->endpoints[endpoint->endpointID] = NULL;
		delete endpoint;
		return NULL;
	}
}

SVCEndpoint* SVC::listenConnection(int timeout){
	SVCPacket* request;
	request=this->connectionRequests->dequeueWait(timeout);
	if (request!=NULL){
		//-- there is connection request, read for endpointID
		uint64_t endpointID = *((uint64_t*)&request->packet);
		SVCEndpoint* ep = new SVCEndpoint(this, false);
		ep->request = request;
		//-- set the endpointID and bind to unix socket
		ep->bindToEndpointID(endpointID);
		//-- then connect to the "already created daemon socket"
		ep->connectToDaemon();
		this->endpoints[endpointID] = ep;
		return ep;
	}
	else{		
		return NULL;
	}
}
//--	SVCENDPOINT class	//

SVCEndpoint::SVCEndpoint(SVC* svc, bool isInitiator){
	this->svc = svc;
	this->isInitiator = isInitiator;
	printf("\nnew endpoint create: "); printBuffer((uint8_t*)&this->endpointID, ENDPOINTID_LENGTH); fflush(stdout);
};

void SVCEndpoint::setRemoteHost(SVCHost* remoteHost){
	this->remoteHost = remoteHost;
}

void SVCEndpoint::changeEndpointID(uint64_t endpointID){
	this->endpointID = endpointID;
}

void SVCEndpoint::bindToEndpointID(uint64_t endpointID){
	this->endpointID = endpointID;
	//--	create a socket for listening to data
	//-- bind app endpoint socket
	this->sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	this->endpointSockPath = SVC_ENDPOINT_APP_PATH_PREFIX + to_string(endpointID);	
	struct sockaddr_un sockAddr;
	memset(&sockAddr, 0, sizeof(sockAddr));
	sockAddr.sun_family = AF_LOCAL;
	memcpy(sockAddr.sun_path, this->endpointSockPath.c_str(), endpointSockPath.size());
	bind(this->sock, (struct sockaddr*)&sockAddr, sizeof(sockAddr));
	//-- create a packet handler to process incoming packets
	if (this->packetHandler!=NULL) delete this->packetHandler;
	this->packetHandler = new PacketHandler(this->sock);
}

void SVCEndpoint::connectToDaemon(){
	string endpointDmnSockPath = SVC_ENDPOINT_DMN_PATH_PREFIX + to_string(this->endpointID);
	struct sockaddr_un dmnEndpointAddr;
	memset(&dmnEndpointAddr, 0, sizeof(dmnEndpointAddr));
	dmnEndpointAddr.sun_family = AF_LOCAL;
	memcpy(dmnEndpointAddr.sun_path, endpointDmnSockPath.c_str(), endpointDmnSockPath.size());
	connect(this->sock, (struct sockaddr*)&dmnEndpointAddr, sizeof(dmnEndpointAddr));
}

bool SVCEndpoint::negotiate(){
	
	if (this->isInitiator){
		//--	send SVC_CMD_CONNECT_INNER1
		SVCPacket* packet = new SVCPacket(this->endpointID);
		packet->setCommand(SVC_CMD_CONNECT_INNER1);
		//-- get challenge secret and challenge
		string challenge = this->svc->authenticator->generateChallenge();
		string challengeSecret = this->svc->authenticator->getChallengeSecret();
		packet->pushCommandParam((uint8_t*)challenge.c_str(), challenge.size());
		packet->pushCommandParam((uint8_t*)&this->svc->appID, APPID_LENGTH);
		packet->pushCommandParam((uint8_t*)challengeSecret.c_str(), challengeSecret.size());
		uint32_t remoteAddr = this->remoteHost->getHostAddress();
		packet->pushCommandParam((uint8_t*)&remoteAddr, HOST_ADDR_LENGTH);
		int sendrs = this->packetHandler->sendPacket(packet);
		//--	wait for SVC_CMD_CONNECT_INNER4
		printf("\nwait for CONNECT_INNER4");
		return this->packetHandler->waitCommand(SVC_CMD_CONNECT_INNER4, this->endpointID, packet, SVC_DEFAULT_TIMEOUT);
	}
	else{
		//-- read challenge from packet
		uint8_t* param = (uint8_t*)malloc(SVC_DEFAULT_BUFSIZ);
		uint16_t paramLen;
		this->request->popCommandParam(param, &paramLen);
		string challengeReceived = hexToString(param, paramLen);
		printf("\nChallenge received: %s", challengeReceived.c_str());
		return false;
	}
}

SVCEndpoint::~SVCEndpoint(){
	delete this->packetHandler;
	unlink(this->endpointSockPath.c_str());
}

int SVCEndpoint::sendData(const uint8_t* data, size_t dalalen, uint8_t priority, bool tcp){
	return 0;
}

int SVCEndpoint::readData(uint8_t* data, size_t* len){
	return 0;
}

