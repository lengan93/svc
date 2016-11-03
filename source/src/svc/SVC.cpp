#include "SVC.h"

//--	SVC IMPLEMENTATION	--//

uint16_t SVC::endpointCounter = 0;

SVC::SVC(string appID, SVCAuthenticator* authenticator){
	
	this->working = false;
	this->sha256 = new SHA256();
	this->incomingQueue = new MutexedQueue<SVCPacket*>();
	this->outgoingQueue = new MutexedQueue<SVCPacket*>();
	this->tobesentQueue = new MutexedQueue<SVCPacket*>();
	
	const char* errorString;
	

	struct sockaddr_un appSockAddr;
	struct sockaddr_un dmnSockAddr;	
	
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	
	//--	copy param
	this->authenticator = authenticator;
	
	//--	check if the app is running
	string appIDHashed = this->sha256->hash(appID);
	uint8_t* appIDBin;
	stringToHex(appIDHashed.substr(0, 8), &appIDBin); //-- extract first 32 bits of hash string
	this->appID = *((uint32_t*)appIDBin);
	
	//--	BLOCK ALL KIND OF SIGNAL
	sigset_t sig;
	sigfillset(&sig);
	
	if (pthread_sigmask(SIG_BLOCK, &sig, NULL)!=0){
		errorString = SVC_ERROR_CRITICAL;
		goto errorInit;
	}	
	
	this->appSockPath = SVC_CLIENT_PATH_PREFIX + to_string(this->appID);	
	//- bind app socket
	this->appSocket = socket(AF_LOCAL, SOCK_DGRAM, 0);
	memset(&appSockAddr, 0, sizeof(appSockAddr));
	appSockAddr.sun_family = AF_LOCAL;
	memcpy(appSockAddr.sun_path, appSockPath.c_str(), this->appSockPath.size());
	if (bind(this->appSocket, (struct sockaddr*)&appSockAddr, sizeof(appSockAddr))==-1){
		errorString = SVC_ERROR_BINDING;		
		goto errorInit;
	}
	//-- then create reading thread
	if (pthread_create(&this->readingThread, &attr, svc_reading_loop, this) !=0){
		errorString = SVC_ERROR_CRITICAL;
		delete this->incomingQueue;
		goto error;
	}
	
	//-- connect to daemon socket
	memset(&dmnSockAddr, 0, sizeof(dmnSockAddr));
	dmnSockAddr.sun_family = AF_LOCAL;
	memcpy(dmnSockAddr.sun_path, SVC_DAEMON_PATH.c_str(), SVC_DAEMON_PATH.size());
	if (connect(this->appSocket, (struct sockaddr*) &dmnSockAddr, sizeof(dmnSockAddr)) == -1){
		errorString = SVC_ERROR_CONNECTING;		
		goto error;
	}	
	//-- then create writing thread
	if (pthread_create(&this->writingThread, &attr, svc_writing_loop, this) !=0){
		errorString = SVC_ERROR_CRITICAL;
		goto error;
	}
		
	goto success;
	
	error:		
		unlink(this->appSockPath.c_str());
	errorInit:
		delete this->sha256;
		delete this->incomingQueue;
		delete this->outgoingQueue;
		delete this->tobesentQueue;
		throw errorString;
		
	success:
		this->endpoints.clear();
		this->connectionRequests = new MutexedQueue<SVCPacket*>();		
		this->incomingPacketHandler = new PacketHandler(incomingQueue, svc_incoming_packet_handler, this);	
		this->outgoingPacketHandler = new PacketHandler(outgoingQueue, svc_outgoing_packet_handler, this);
		this->working = true;		
}

void SVC::shutdown(){

	if (this->working){
		this->working = false;
		
		//-- send shutdown request to all SVCEndpoint instances	
		for (auto& it : endpoints){
			if (it.second!=NULL){
				SVCEndpoint* ep = (SVCEndpoint*)it.second;
				this->endpoints[ep->endpointID] = NULL; //-- just remove reference, <key, NULL> still left
				delete ep; //-- ep destructor calls shutdown
			}			
		}
		
		//-- remove all <key, NULL> instance
		this->endpoints.clear();
		
		unlink(this->appSockPath.c_str());
		delete this->incomingPacketHandler;
		delete this->outgoingPacketHandler;
		delete this->sha256;
		delete this->incomingQueue;
		delete this->outgoingQueue;
		delete this->tobesentQueue;
	}
}

SVC::~SVC(){
	shutdown();
}

void SVC::svc_incoming_packet_handler(SVCPacket* packet, void* args){
	SVC* _this = (SVC*)args;
	
	uint8_t infoByte = packet->packet[INFO_BYTE];

	if ((infoByte & SVC_COMMAND_FRAME) != 0x00){
		//-- incoming command
		enum SVCCommand cmd = (enum SVCCommand)packet->packet[SVC_PACKET_HEADER_LEN];
		switch(cmd){
			case SVC_CMD_CONNECT_INNER2:
				_this->connectionRequests->enqueue(new SVCPacket(packet));
				break;
			default:			
				break;
		}
		//-- all command are processed then destroyed by default
		packet->packet[INFO_BYTE] |= SVC_TOBE_REMOVED;
	}
	else{
		//-- svc doesn't allow data
		packet->packet[INFO_BYTE] |= SVC_TOBE_REMOVED;
	}	
}

void SVC::svc_outgoing_packet_handler(SVCPacket* packet, void* args){
	SVC* _this = (SVC*)args;
	//-- for now just forward
	_this->tobesentQueue->enqueue(packet);
}

void* SVC::svc_reading_loop(void* args){
	SVC* _this = (SVC*)args;
	
	//-- read from unix socket then enqueue to incoming queue
	uint8_t* const buffer = (uint8_t*)malloc(SVC_DEFAULT_BUFSIZ);
	ssize_t readrs;
		
	while (_this->working){
		do{
			readrs = recv(_this->appSocket, buffer, SVC_DEFAULT_BUFSIZ, MSG_DONTWAIT);
		}
		while((readrs==-1) && _this->working);
		
		if (readrs>0){
			_this->incomingQueue->enqueue(new SVCPacket(buffer, readrs));
		}
		//else: read received nothing
	}
	
	delete buffer;
}

void* SVC::svc_writing_loop(void* args){
	SVC* _this = (SVC*)args;
	
	int sendrs;
	SVCPacket* packet;
	while (_this->working){
		//packet = _this->writingQueue->dequeueWait(-1);
		packet = _this->tobesentQueue->dequeue();
		if (packet!=NULL){
			//-- send this packet to underlayer
			sendrs = send(_this->appSocket, packet->packet, packet->dataLen, 0);
			//-- remove the packet after sending
			delete packet;
			//-- TODO: check this send result for futher decision
		}	
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
	if (endpoint->bindToEndpointID(endpointID) == -1){
		delete endpoint;
		return NULL;
	}
	else{	
		endpoint->setRemoteHost(remoteHost);
		//-- add this endpoint to be handled
		this->endpoints[endpoint->endpointID] = endpoint;
		
		//-- send SVC_CMD_CREATE_ENDPOINT to daemon
		SVCPacket* packet = new SVCPacket(endpoint->endpointID);
		packet->setCommand(SVC_CMD_CREATE_ENDPOINT);
		//int sendrs = 
		this->outgoingQueue->enqueue(packet);
		
		//-- wait for response from daemon endpoint then connect the app endpoint socket to daemon endpoint address
		uint32_t responseLen;	
		fflush(stdout);
		printf("\nwait for SVC_CMD_CREATE_ENDPOINT"); fflush(stdout);
		//-- create new packet because the old packet has been destroyed
		if (endpoint->incomingPacketHandler->waitCommand(SVC_CMD_CREATE_ENDPOINT, endpoint->endpointID, SVC_DEFAULT_TIMEOUT)){
			printf("\nwait create_endpoint success, call connectToDaemon");
			endpoint->connectToDaemon();
			return endpoint;
		}
		else{
			printf("\nwait create_endpoint failed");
			//-- remove endpoint from the map			
			this->endpoints.erase(endpoint->endpointID);
			delete endpoint;
			return NULL;
		}
	}
}

SVCEndpoint* SVC::listenConnection(int timeout){
	SVCPacket* request;
	request=this->connectionRequests->dequeueWait(timeout);
	if (request!=NULL){
		//-- there is connection request, read for endpointID
		uint64_t endpointID = *((uint64_t*)request->packet);		
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
	this->incomingPacketHandler = NULL;
	this->outgoingPacketHandler = NULL;
	this->incomingQueue = new MutexedQueue<SVCPacket*>();
	this->outgoingQueue = new MutexedQueue<SVCPacket*>();
	this->tobesentQueue = new MutexedQueue<SVCPacket*>();
	this->dataholdQueue = new MutexedQueue<SVCPacket*>();
};

void SVCEndpoint::svc_endpoint_incoming_packet_handler(SVCPacket* packet, void* args){
	SVCEndpoint* _this = (SVCEndpoint*)args;

	static uint8_t param[SVC_DEFAULT_BUFSIZ];
	static uint16_t paramLen;
	
	uint8_t infoByte = packet->packet[INFO_BYTE];

	if ((infoByte & SVC_COMMAND_FRAME) != 0x00){
		//-- process incoming command
		SVCCommand cmd = (SVCCommand)packet->packet[CMD_BYTE];
		switch (cmd){				
			case SVC_CMD_CONNECT_INNER4:
				printf("\nCONNECT_INNER4 received");
				//--	new endpointID
				packet->popCommandParam(param, &paramLen);
				_this->changeEndpointID(*((uint64_t*)param));
				//-- replace packet endpointID with the new one
				memcpy(packet->packet, param, ENDPOINTID_LENGTH);		
				packet->popCommandParam(param, &paramLen);
				_this->challengeReceived = string((char*)param, paramLen);
				//printf("\nchallenge received: %s", challengeReceived.c_str()); fflush(stdout);
		
				//--	resolve challenge then send back to daemon
				_this->challengeSecretReceived = _this->svc->authenticator->resolveChallenge(_this->challengeReceived);
				//printf("\nChallenge secret resolved: %s", challengeSecretReceived.c_str()); fflush(stdout);
		
				//- packet updated with new endpointID
				packet->switchCommand(SVC_CMD_CONNECT_INNER5);
				//packet->packet[INFO_BYTE] &= ~SVC_INCOMING_PACKET;
				packet->pushCommandParam((uint8_t*)_this->challengeSecretReceived.c_str(), _this->challengeSecretReceived.size());
				_this->outgoingQueue->enqueue(packet);				
				break;
				
			case SVC_CMD_CONNECT_INNER6:				
				printf("\nSVC_CMD_CONNECT_INNER6 received"); fflush(stdout);
				//-- pop solution proof and check
				packet->popCommandParam(param, &paramLen);
				if (_this->svc->authenticator->verifyProof(_this->challengeSecretSent, string((char*)param, paramLen))){
					//-- proof verified, generate proof then send back to daemon
					_this->proof = _this->svc->authenticator->generateProof(_this->challengeSecretReceived);
					packet->switchCommand(SVC_CMD_CONNECT_INNER7);
					//packet->packet[INFO_BYTE] &= ~SVC_INCOMING_PACKET;
					packet->pushCommandParam((uint8_t*)_this->proof.c_str(), _this->proof.size());
					_this->outgoingQueue->enqueue(packet);
					//-- ok, connection established
					_this->isAuth = true;
				}
				else{
					printf("\nproof verification failed");
					//-- proof verification failed
					packet->packet[INFO_BYTE] |= SVC_TOBE_REMOVED;
					_this->isAuth = false;
				}
				break;
				
			case SVC_CMD_CONNECT_INNER8:					
				printf("\nreceived CONNECT_INNER8"); fflush(stdout);					
				//-- verify the client's proof
				packet->popCommandParam(param, &paramLen);
				if (_this->svc->authenticator->verifyProof(_this->challengeSecretSent, string((char*)param, paramLen))){
					//-- send confirm to daemon
					packet->setCommand(SVC_CMD_CONNECT_INNER9);
					//packet->packet[INFO_BYTE] &= ~SVC_INCOMING_PACKET;
					_this->outgoingQueue->enqueue(packet);
					_this->isAuth = true;
				}
				else{
					//-- proof verification failed
					packet->packet[INFO_BYTE] |= SVC_TOBE_REMOVED;
					_this->isAuth = false;
				}
				break;
			
			default:
				//-- to be removed
				packet->packet[INFO_BYTE] |= SVC_TOBE_REMOVED;
				break;
		}
	}
	else{
		//-- processing incoming data
		_this->dataholdQueue->enqueue(packet);
	}
}

void SVCEndpoint::svc_endpoint_outgoing_packet_handler(SVCPacket* packet, void* args){
	SVCEndpoint* _this = (SVCEndpoint*)args;		
	//-- for now just forward
	_this->tobesentQueue->enqueue(packet);
}

void* SVCEndpoint::svc_endpoint_reading_loop(void* args){
	SVCEndpoint* _this = (SVCEndpoint*)args;
	//-- read from unix socket then enqueue to incoming queue
	uint8_t* const buffer = (uint8_t*)malloc(SVC_DEFAULT_BUFSIZ);
	ssize_t readrs;
		
	while (_this->working){
		do{
			readrs = recv(_this->sock, buffer, SVC_DEFAULT_BUFSIZ, MSG_DONTWAIT);
		}
		while((readrs==-1) && _this->working);
		
		if (readrs>0){
			_this->incomingQueue->enqueue(new SVCPacket(buffer, readrs));
		}
		//else: read received nothing
	}
	
	delete buffer;
}

void* SVCEndpoint::svc_endpoint_writing_loop(void* args){
	SVCEndpoint* _this = (SVCEndpoint*)args;
	int sendrs;
	SVCPacket* packet;
	while (_this->working){
		//packet = _this->writingQueue->dequeueWait(-1);
		packet = _this->tobesentQueue->dequeue();
		if (packet!=NULL){
			//-- send this packet to underlayer
			sendrs = send(_this->sock, packet->packet, packet->dataLen, 0);
			//-- remove the packet after sending
			delete packet;
			//-- TODO: check this send result for futher decision
		}
	}
}

void SVCEndpoint::setRemoteHost(SVCHost* remoteHost){
	this->remoteHost = remoteHost;
}

void SVCEndpoint::changeEndpointID(uint64_t endpointID){
	//-- remove old record in endpoints
	this->svc->endpoints.erase(this->endpointID);
	//-- update
	this->svc->endpoints[endpointID] = this;
	this->endpointID = endpointID;
}

int SVCEndpoint::bindToEndpointID(uint64_t endpointID){
	
	this->endpointID = endpointID;
	//-- bind app endpoint socket
	this->sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	this->endpointSockPath = SVC_ENDPOINT_APP_PATH_PREFIX + hexToString((uint8_t*)&this->endpointID, ENDPOINTID_LENGTH);	
	struct sockaddr_un sockAddr;
	memset(&sockAddr, 0, sizeof(sockAddr));
	sockAddr.sun_family = AF_LOCAL;
	memcpy(sockAddr.sun_path, this->endpointSockPath.c_str(), endpointSockPath.size());
	if (bind(this->sock, (struct sockaddr*)&sockAddr, sizeof(sockAddr)) == -1){
		return -1;
	}
	else{
		//-- create new reading thread
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		if (pthread_create(&this->readingThread, &attr, svc_endpoint_reading_loop, this) !=0){
			return -1;
		}
		//-- create a packet handler to process incoming packets		
		this->incomingPacketHandler = new PacketHandler(this->incomingQueue, svc_endpoint_incoming_packet_handler, this);
		this->working = true;
		return 0;
	}
}

int SVCEndpoint::connectToDaemon(){
	string endpointDmnSockPath = SVC_ENDPOINT_DMN_PATH_PREFIX + hexToString((uint8_t*)&this->endpointID, ENDPOINTID_LENGTH);
	struct sockaddr_un dmnEndpointAddr;
	memset(&dmnEndpointAddr, 0, sizeof(dmnEndpointAddr));
	dmnEndpointAddr.sun_family = AF_LOCAL;
	memcpy(dmnEndpointAddr.sun_path, endpointDmnSockPath.c_str(), endpointDmnSockPath.size());
	if (connect(this->sock, (struct sockaddr*)&dmnEndpointAddr, sizeof(dmnEndpointAddr)) != -1){
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		if (pthread_create(&this->writingThread, &attr, svc_endpoint_writing_loop, this) !=0){
			return -1;
		}
		//-- create a packet handler to process incoming packets		
		this->outgoingPacketHandler = new PacketHandler(this->outgoingQueue, svc_endpoint_outgoing_packet_handler, this);
		return 0;
	}
	else{
		return -1;
	}
}

bool SVCEndpoint::negotiate(){	
	
	uint8_t* param = (uint8_t*)malloc(SVC_DEFAULT_BUFSIZ);
	uint16_t paramLen;
	SVCPacket* packet;
	
	if (this->isInitiator){
		//--	send SVC_CMD_CONNECT_INNER1
		packet = new SVCPacket(this->endpointID);
		packet->setCommand(SVC_CMD_CONNECT_INNER1);
		//-- get challenge secret and challenge		
		this->challengeSecretSent = this->svc->authenticator->generateChallengeSecret();
		//printf("\nchallenge secret sent: %s", challengeSecretSent.c_str());
		this->challengeSent = this->svc->authenticator->generateChallenge(challengeSecretSent);
		//printf("\nchallenge sent: %s", challengeSent.c_str());
		packet->pushCommandParam((uint8_t*)challengeSent.c_str(), challengeSent.size());
		packet->pushCommandParam((uint8_t*)&this->svc->appID, APPID_LENGTH);
		packet->pushCommandParam((uint8_t*)challengeSecretSent.c_str(), challengeSecretSent.size());
		uint32_t remoteAddr = this->remoteHost->getHostAddress();
		packet->pushCommandParam((uint8_t*)&remoteAddr, HOST_ADDR_LENGTH);
		//-- recvPacket swallows the packet
		this->outgoingQueue->enqueue(packet);
		
		printf("\nwait for CONNECT_INNER4");
		if (!this->incomingPacketHandler->waitCommand(SVC_CMD_CONNECT_INNER4, this->endpointID, SVC_DEFAULT_TIMEOUT)){
			this->isAuth = false;
		}
		if (!this->incomingPacketHandler->waitCommand(SVC_CMD_CONNECT_INNER6, this->endpointID, SVC_DEFAULT_TIMEOUT)){
			this->isAuth = false;
		}
	}
	else{
		//-- read challenge from request packet
		this->request->popCommandParam(param, &paramLen);
		this->challengeReceived = string((char*)param, paramLen);
		//printf("\nChallenge received: %s", challengeReceived.c_str()); fflush(stdout);
		
		//-- resolve this challenge to get challenge secret
		this->challengeSecretReceived = this->svc->authenticator->resolveChallenge(this->challengeReceived);
		//printf("\nChallenge secret resolved: %s", challengeSecretReceived.c_str()); fflush(stdout);
		//-- generate proof
		this->proof = this->svc->authenticator->generateProof(this->challengeSecretReceived);
		//printf("\nProof generated: %s", proof.c_str()); fflush(stdout);
		
		//-- generate challenge
		this->challengeSecretSent = this->svc->authenticator->generateChallengeSecret();
		//printf("\nchallengeSecretSent: %s", challengeSecretSent.c_str());
		this->challengeSent = this->svc->authenticator->generateChallenge(this->challengeSecretSent);
		//printf("\nchallengeSent: %s", challengeSent.c_str());
		
		packet->setCommand(SVC_CMD_CONNECT_INNER3);
		packet->pushCommandParam((uint8_t*)this->challengeSent.c_str(), this->challengeSent.size());
		packet->pushCommandParam((uint8_t*)this->proof.c_str(), this->proof.size());
		packet->pushCommandParam((uint8_t*)this->challengeSecretSent.c_str(), this->challengeSecretSent.size());
		packet->pushCommandParam((uint8_t*)this->challengeSecretReceived.c_str(),  this->challengeSecretReceived.size());
		//int sendrs = 		
		this->outgoingQueue->enqueue(packet);
		
		printf("\nwait for CONNECT_INNER8"); fflush(stdout);
		if (!this->incomingPacketHandler->waitCommand(SVC_CMD_CONNECT_INNER8, this->endpointID, SVC_DEFAULT_TIMEOUT)){
			this->isAuth = false;
		}
	}
	
	delete param;	
	return this->isAuth;
}

void SVCEndpoint::shutdown(){
	//printf("\nendpoint shutdown called in thread: %d - ", (int)pthread_self()); printBuffer((uint8_t*)&this->endpointID, ENDPOINTID_LENGTH);
	if (this->working){
		//printf("\ninside this->working check");		
		//-- send terminated packet to daemon endpoint
		SVCPacket* packet = new SVCPacket(this->endpointID);
		packet->setCommand(SVC_CMD_SHUTDOWN_ENDPOINT);
		this->outgoingQueue->enqueue(packet);
		
		//-- remove itself from svc collection, don't call erase because svc shutdown may iterate through the endpoints
		this->svc->endpoints[this->endpointID]= NULL;
		
		//-- clean up
		this->working = false;
		
		if (this->incomingPacketHandler != NULL) delete this->incomingPacketHandler;
		if (this->outgoingPacketHandler != NULL) delete this->outgoingPacketHandler;
		delete this->incomingQueue;
		delete this->outgoingQueue;
		delete this->tobesentQueue;
		delete this->dataholdQueue;
		unlink(this->endpointSockPath.c_str());
	}
}

SVCEndpoint::~SVCEndpoint(){
	shutdown();
}

int SVCEndpoint::sendData(const uint8_t* data, uint32_t dataLen, uint8_t priority, bool tcp){
	if (this->isAuth){
		//-- try to send
		SVCPacket* packet = new SVCPacket(this->endpointID);
		packet->setData(data, dataLen);
		this->outgoingQueue->enqueue(packet);
		return 0;
	}
	else{
		return -1;
	}
}

int SVCEndpoint::readData(uint8_t* data, uint32_t* len){
	if (this->isAuth){
		SVCPacket* packet = this->dataholdQueue->dequeue();//Wait(-1);
		if (packet!=NULL){
			memcpy(data, packet->packet, packet->dataLen);
			*len = packet->dataLen;
			delete packet;
			return 0;
		}
		else{
			return -1;
		}
	}
	else{
		return -1;
	}
}

