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
	this->appSockPath = SVC_CLIENT_PATH_PREFIX + to_string(this->appID);
	
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
	printf("\nSVC destructed\n");
	fflush(stdout);
}


SVC::~SVC(){
	this->shutdown();
}

void SVC::svc_command_packet_handler(SVCPacket* packet, void* args){
	SVC* _this = (SVC*)args;
	enum SVCCommand cmd = (enum SVCCommand)packet->packet[SVC_PACKET_HEADER_LEN];
	switch(cmd){
		case SVC_CMD_CONNECT_INNER2:
			_this->connectionRequests->enqueue(packet);		
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
	endpointID |= ++SVC::endpointCounter;
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
		uint64_t endpointID = *((uint64_t*)request->packet);
		printf("\nconnection request from: "); printBuffer((uint8_t*)&endpointID, ENDPOINTID_LENGTH);
		SVCEndpoint* ep = new SVCEndpoint(this, false);
		ep->request = request;
		//-- set the endpointID and bind to unix socket
		printf("\nendpointID right before calling to bind: "); printBuffer((uint8_t*)&endpointID, ENDPOINTID_LENGTH); fflush(stdout);
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
	this->packetHandler = NULL;
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
	printf("\nendpointID inside bind: "); printBuffer((uint8_t*)&endpointID, ENDPOINTID_LENGTH); fflush(stdout);
	//-- bind app endpoint socket
	this->sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	this->endpointSockPath = SVC_ENDPOINT_APP_PATH_PREFIX + hexToString((uint8_t*)&this->endpointID, ENDPOINTID_LENGTH);	
	struct sockaddr_un sockAddr;
	memset(&sockAddr, 0, sizeof(sockAddr));
	sockAddr.sun_family = AF_LOCAL;
	memcpy(sockAddr.sun_path, this->endpointSockPath.c_str(), endpointSockPath.size());
	bind(this->sock, (struct sockaddr*)&sockAddr, sizeof(sockAddr));
	printf("\nsvc endpoint binded to: %s", this->endpointSockPath.c_str());
	//-- create a packet handler to process incoming packets
	if (this->packetHandler!=NULL) delete this->packetHandler;
	this->packetHandler = new PacketHandler(this->sock);
}

void SVCEndpoint::connectToDaemon(){
	string endpointDmnSockPath = SVC_ENDPOINT_DMN_PATH_PREFIX + hexToString((uint8_t*)&this->endpointID, ENDPOINTID_LENGTH);
	struct sockaddr_un dmnEndpointAddr;
	memset(&dmnEndpointAddr, 0, sizeof(dmnEndpointAddr));
	dmnEndpointAddr.sun_family = AF_LOCAL;
	memcpy(dmnEndpointAddr.sun_path, endpointDmnSockPath.c_str(), endpointDmnSockPath.size());
	connect(this->sock, (struct sockaddr*)&dmnEndpointAddr, sizeof(dmnEndpointAddr));
	printf("\nsvc endpoint connected to: %s", endpointDmnSockPath.c_str());
}

bool SVCEndpoint::negotiate(){
	
	string challengeSecretSent;
	string challengeSecretReceived;
	string challengeSent;
	string challengeReceived;
	string proof;
	
	
	uint8_t* param = (uint8_t*)malloc(SVC_DEFAULT_BUFSIZ);
	uint16_t paramLen;
	SVCPacket* packet = new SVCPacket(this->endpointID);
	
	bool rs = false;
	
	if (this->isInitiator){
		//--	send SVC_CMD_CONNECT_INNER1		
		packet->setCommand(SVC_CMD_CONNECT_INNER1);
		//-- get challenge secret and challenge		
		challengeSecretSent = this->svc->authenticator->generateChallengeSecret();
		printf("\nchallenge secret sent: %s", challengeSecretSent.c_str());
		challengeSent = this->svc->authenticator->generateChallenge(challengeSecretSent);
		printf("\nchallenge sent: %s", challengeSent.c_str());
		packet->pushCommandParam((uint8_t*)challengeSent.c_str(), challengeSent.size());
		packet->pushCommandParam((uint8_t*)&this->svc->appID, APPID_LENGTH);
		packet->pushCommandParam((uint8_t*)challengeSecretSent.c_str(), challengeSecretSent.size());
		uint32_t remoteAddr = this->remoteHost->getHostAddress();
		packet->pushCommandParam((uint8_t*)&remoteAddr, HOST_ADDR_LENGTH);
		int sendrs = this->packetHandler->sendPacket(packet);
		//--	wait for SVC_CMD_CONNECT_INNER4
		printf("\nwait for CONNECT_INNER4");
		if (this->packetHandler->waitCommand(SVC_CMD_CONNECT_INNER4, this->endpointID, packet, SVC_DEFAULT_TIMEOUT)){
			printf("\nCONNECT_INNER4 received");
			//--	new endpointID
			packet->popCommandParam(param, &paramLen);
			this->changeEndpointID(*((uint64_t*)param));
			packet->popCommandParam(param, &paramLen);
			challengeReceived = string((char*)param, paramLen);
			printf("\nchallenge received: %s", challengeReceived.c_str()); fflush(stdout);
			
			//--	resolve challenge then send back to daemon
			challengeSecretReceived = this->svc->authenticator->resolveChallenge(challengeReceived);
			printf("\nChallenge secret resolved: %s", challengeSecretReceived.c_str()); fflush(stdout);
			
			packet->switchCommand(SVC_CMD_CONNECT_INNER5);
			packet->pushCommandParam((uint8_t*)challengeSecretReceived.c_str(), challengeSecretReceived.size());
			this->packetHandler->sendPacket(packet);
			//--	wait for CONNECT_INNER6
			if (this->packetHandler->waitCommand(SVC_CMD_CONNECT_INNER6, this->endpointID, packet, SVC_DEFAULT_TIMEOUT)){
				rs = true;
			}
			else{
				rs = false;
			}
		}
		else{			
			rs = false;
		}
	}
	else{
		//-- read challenge from request packet
		this->request->popCommandParam(param, &paramLen);
		string challengeReceived = string((char*)param, paramLen);
		printf("\nChallenge received: %s", challengeReceived.c_str()); fflush(stdout);
		
		//-- resolve this challenge to get challenge secret
		string challengeSecretReceived = this->svc->authenticator->resolveChallenge(challengeReceived);
		printf("\nChallenge secret resolved: %s", challengeSecretReceived.c_str()); fflush(stdout);
		//-- generate proof
		string proof = this->svc->authenticator->generateProof(challengeSecretReceived);
		printf("\nProof generated: %s", proof.c_str()); fflush(stdout);
		
		//-- generate challenge
		challengeSecretSent = this->svc->authenticator->generateChallengeSecret();
		printf("\nchallengeSecretSent: %s", challengeSecretSent.c_str());
		challengeSent = this->svc->authenticator->generateChallenge(challengeSecretSent);
		printf("\nchallengeSent: %s", challengeSent.c_str());
		
		packet->setCommand(SVC_CMD_CONNECT_INNER3);
		packet->pushCommandParam((uint8_t*)challengeSent.c_str(), challengeSent.size());
		packet->pushCommandParam((uint8_t*)proof.c_str(), proof.size());
		packet->pushCommandParam((uint8_t*)challengeSecretSent.c_str(), challengeSecretSent.size());
		packet->pushCommandParam((uint8_t*)challengeSecretReceived.c_str(),  challengeSecretReceived.size());
		int sendrs = this->packetHandler->sendPacket(packet);
		
		//--	wait for SVC_CMD_CONNECT_INNER8
		printf("\nWAIT FOR CONNECT_INNER8"); fflush(stdout);
		rs = this->packetHandler->waitCommand(SVC_CMD_CONNECT_INNER8, this->endpointID, packet, SVC_DEFAULT_TIMEOUT);
	}
	
	delete param;
	delete packet;
	return rs;
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

