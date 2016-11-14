#include "SVC.h"

//--	SVC IMPLEMENTATION	--//

uint16_t SVC::endpointCounter = 0;

SVC::SVC(std::string appID, SVCAuthenticator* authenticator){

	this->working = true;
	this->readingThread = 0;
	this->writingThread = 0;
	this->sha256 = new SHA256();		
	
	struct sockaddr_un appSockAddr;
	struct sockaddr_un dmnSockAddr;	
	
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	
	//--	copy param
	this->authenticator = authenticator;
	
	//--	check if the app is running
	std::string appIDHashed = this->sha256->hash(appID);
	stringToHex(appIDHashed.substr(0, 8), (uint8_t*)&this->appID); //-- extract first 32 bits of hash string
	
	//--	BLOCK ALL KIND OF SIGNAL
	sigset_t sig;
	sigfillset(&sig);
	if (pthread_sigmask(SIG_BLOCK, &sig, NULL)!=0){		
		delete this->sha256;
		throw SVC_ERROR_CRITICAL;
	}	
	else{
		this->appSockPath = std::string(SVC_CLIENT_PATH_PREFIX) + to_string(this->appID);	
		//- bind app socket
		this->appSocket = socket(AF_LOCAL, SOCK_DGRAM, 0);
		memset(&appSockAddr, 0, sizeof(appSockAddr));
		appSockAddr.sun_family = AF_LOCAL;
		memcpy(appSockAddr.sun_path, appSockPath.c_str(), this->appSockPath.size());
		if (bind(this->appSocket, (struct sockaddr*)&appSockAddr, sizeof(appSockAddr))==-1){			
			delete this->sha256;
			throw SVC_ERROR_BINDING;
		}
		else{
			//-- then create reading thread
			if (pthread_create(&this->readingThread, &attr, svc_reading_loop, this) !=0){				
				unlink(this->appSockPath.c_str());
				delete this->sha256;
				throw SVC_ERROR_CRITICAL;
			}
			else{			
				//-- connect to daemon socket
				memset(&dmnSockAddr, 0, sizeof(dmnSockAddr));
				dmnSockAddr.sun_family = AF_LOCAL;
				memcpy(dmnSockAddr.sun_path, SVC_DAEMON_PATH.c_str(), SVC_DAEMON_PATH.size());
				if (connect(this->appSocket, (struct sockaddr*) &dmnSockAddr, sizeof(dmnSockAddr)) == -1){						
					this->working = false;
					pthread_join(this->readingThread, NULL);
					unlink(this->appSockPath.c_str());
					delete this->sha256;
					throw SVC_ERROR_CONNECTING;
				}
				else{	
					//-- then create writing thread
					if (pthread_create(&this->writingThread, &attr, svc_writing_loop, this) !=0){
						this->working = false;
						pthread_join(this->readingThread, NULL);
						unlink(this->appSockPath.c_str());
						delete this->sha256;
						throw SVC_ERROR_CRITICAL;
					}
					else{
						//-- svc successfully created
						this->endpoints.clear();				
						this->incomingPacketHandler = new PacketHandler(&this->incomingQueue, svc_incoming_packet_handler, this);		
						this->outgoingPacketHandler = new PacketHandler(&this->outgoingQueue, svc_outgoing_packet_handler, this);
					}
				}
			}
		}
	}
}

void SVC::shutdown(){

	if (this->working){
		//-- send shutdown request to all SVCEndpoint instances	
		for (auto& it : endpoints){
			if (it.second!=NULL){
				SVCEndpoint* ep = (SVCEndpoint*)it.second;
				this->endpoints[ep->endpointID] = NULL; //-- just remove reference, <key, NULL> still left
				delete ep; //-- ep destructor calls shutdown
			}
		}
			
		this->working = false;
		
		//-- stop reading packets
		if (this->readingThread !=0) pthread_join(this->readingThread, NULL);
		
		//-- process residual incoming packets
		this->incomingPacketHandler->stopWorking();
		this->incomingPacketHandler->waitStop();
		delete this->incomingPacketHandler;
		
		//-- process residual outgoing packets
		this->outgoingPacketHandler->stopWorking();
		this->outgoingPacketHandler->waitStop();
		delete this->outgoingPacketHandler;
		
		//-- stop writing packets
		if (this->writingThread!=0) pthread_join(this->writingThread, NULL);	
		unlink(this->appSockPath.c_str());
				
		//-- remove queues and intances
		delete this->sha256;		
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
		enum SVCCommand cmd = (enum SVCCommand)packet->packet[CMD_BYTE];
		uint64_t endpointID = *((uint64_t*)packet->packet);
		switch(cmd){
		
			case SVC_CMD_CONNECT_INNER2:
				_this->connectionRequests.enqueue(packet);
				break;
				
			default:
				delete packet;		
				break;
		}
		_this->incomingPacketHandler->notifyCommand(cmd, endpointID);
	}
	else{
		//-- svc doesn't allow data
		delete packet;
	}	
}

void SVC::svc_outgoing_packet_handler(SVCPacket* packet, void* args){
	SVC* _this = (SVC*)args;
	//-- for now just forward
	_this->tobesentQueue.enqueue(packet);	
}

void* SVC::svc_reading_loop(void* args){
	SVC* _this = (SVC*)args;
	
	//-- read from unix socket then enqueue to incoming queue
	uint8_t buffer[SVC_DEFAULT_BUFSIZ];
	int readrs;
		
	while (_this->working){
		do{
			readrs = recv(_this->appSocket, buffer, SVC_DEFAULT_BUFSIZ, MSG_DONTWAIT);
		}
		while((readrs==-1) && _this->working);
		
		if (readrs>0){			
			_this->incomingQueue.enqueue(new SVCPacket(buffer, readrs));
		}
		//else: read received nothing
	}	
	pthread_exit(EXIT_SUCCESS);
}

void* SVC::svc_writing_loop(void* args){
	SVC* _this = (SVC*)args;
	
	int sendrs;
	SVCPacket* packet;
	while (_this->working || _this->outgoingQueue.notEmpty() || _this->tobesentQueue.notEmpty()){		
		packet = _this->tobesentQueue.dequeueWait(1000); fflush(stdout);	
		if (packet!=NULL){
			sendrs = send(_this->appSocket, packet->packet, packet->dataLen, 0);		
			//-- remove the packet after sending			
			delete packet;			
			//-- TODO: check this send result for futher decision
		}		
	}
	pthread_exit(EXIT_SUCCESS);
}

//--	SVC PUBLIC FUNCTION IMPLEMENTATION		--//

SVCEndpoint* SVC::establishConnection(SVCHost* remoteHost){
	
	//-- create new endpoint to handle further packets
	SVCEndpoint* endpoint = new SVCEndpoint(this, true);
	uint64_t endpointID = 0;	
	endpointID |= ++SVC::endpointCounter;
	endpointID<<=32;
	endpointID |= this->appID;
	if (endpoint->bindToEndpointID(endpointID) != 0){
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
		this->outgoingQueue.enqueue(packet);
		
		//-- wait for response from daemon endpoint then connect the app endpoint socket to daemon endpoint address
		uint32_t responseLen;	
		fflush(stdout);	
		if (endpoint->incomingPacketHandler->waitCommand(SVC_CMD_CREATE_ENDPOINT, endpoint->endpointID, SVC_DEFAULT_TIMEOUT)){		
			endpoint->connectToDaemon();
			return endpoint;
		}
		else{			
			//-- remove endpoint from the map			
			this->endpoints.erase(endpoint->endpointID);
			delete endpoint;
			return NULL;
		}
	}
}

SVCEndpoint* SVC::listenConnection(int timeout){
	SVCPacket* request;
	request=this->connectionRequests.dequeueWait(timeout);
	if (request!=NULL){
		//-- there is connection request, read for endpointID
		uint64_t endpointID = *((uint64_t*)request->packet);		
		SVCEndpoint* ep = new SVCEndpoint(this, false);
		ep->request = request;
		//-- set the endpointID and bind to unix socket		
		if (ep->bindToEndpointID(endpointID) ==0){
			if (ep->connectToDaemon() == 0){
				this->endpoints[endpointID] = ep;
				return ep;
			}
			else{				
				delete ep;
				return NULL;
			}
		}
		else{			
			delete ep;
			return NULL;
		}
	}
	else{
		return NULL;
	}
}
//--	SVCENDPOINT class	//

SVCEndpoint::SVCEndpoint(SVC* svc, bool isInitiator){
	this->svc = svc;
	this->isInitiator = isInitiator;
	this->request = NULL;
	this->incomingPacketHandler = NULL;
	this->outgoingPacketHandler = NULL;
	this->readingThread = 0;
	this->writingThread = 0;	
};

void SVCEndpoint::svc_endpoint_incoming_packet_handler(SVCPacket* packet, void* args){
	SVCEndpoint* _this = (SVCEndpoint*)args;

	uint8_t param[SVC_DEFAULT_BUFSIZ]="";
	uint16_t paramLen;
	
	uint8_t infoByte = packet->packet[INFO_BYTE];

	if ((infoByte & SVC_COMMAND_FRAME) != 0x00){
		//-- process incoming command
		SVCCommand cmd = (SVCCommand)packet->packet[CMD_BYTE];
		uint64_t endpointID = *((uint64_t*)packet->packet);
		
		switch (cmd){				
			case SVC_CMD_CONNECT_INNER4:				
				//--	new endpointID
				packet->popCommandParam(param, &paramLen);
				_this->changeEndpointID(*((uint64_t*)param));
				//-- replace packet endpointID with the new one
				memcpy(packet->packet, param, ENDPOINTID_LENGTH);		
				packet->popCommandParam(param, &paramLen);
				_this->challengeReceived = std::string((char*)param, paramLen);
				
				//--	resolve challenge then send back to daemon
				_this->challengeSecretReceived = _this->svc->authenticator->resolveChallenge(_this->challengeReceived);
				
				//- packet updated with new endpointID
				packet->switchCommand(SVC_CMD_CONNECT_INNER5);				
				packet->pushCommandParam((uint8_t*)_this->challengeSecretReceived.c_str(), _this->challengeSecretReceived.size());
				_this->outgoingQueue.enqueue(packet);				
				break;
				
			case SVC_CMD_CONNECT_INNER6:								
				//-- pop solution proof and check
				packet->popCommandParam(param, &paramLen);
				if (_this->svc->authenticator->verifyProof(_this->challengeSecretSent, std::string((char*)param, paramLen))){
					//-- proof verified, generate proof then send back to daemon
					_this->proof = _this->svc->authenticator->generateProof(_this->challengeSecretReceived);
					packet->switchCommand(SVC_CMD_CONNECT_INNER7);				
					packet->pushCommandParam((uint8_t*)_this->proof.c_str(), _this->proof.size());
					_this->outgoingQueue.enqueue(packet);
					//-- ok, connection established
					_this->isAuth = true;
				}
				else{					
					//-- proof verification failed
					delete packet;
					_this->isAuth = false;
				}
				break;
				
			case SVC_CMD_CONNECT_INNER8:				
				//-- verify the client's proof
				packet->popCommandParam(param, &paramLen);
				if (_this->svc->authenticator->verifyProof(_this->challengeSecretSent, std::string((char*)param, paramLen))){
					//-- send confirm to daemon
					packet->setCommand(SVC_CMD_CONNECT_INNER9);					
					_this->outgoingQueue.enqueue(packet);
					_this->isAuth = true;
				}
				else{
					//-- proof verification failed
					delete packet;
					_this->isAuth = false;
				}
				break;
			
			default:
				//-- to be removed
				delete packet;
				break;
		}
		_this->incomingPacketHandler->notifyCommand(cmd, endpointID);	
	}
	else{
		//-- processing incoming data
		_this->dataholdQueue.enqueue(packet);
	}
}

void SVCEndpoint::svc_endpoint_outgoing_packet_handler(SVCPacket* packet, void* args){
	SVCEndpoint* _this = (SVCEndpoint*)args;		
	//printf("\nsvc endpoint outgoing forwarding: "); printBuffer(packet->packet, packet->dataLen); fflush(stdout);
	_this->tobesentQueue.enqueue(packet);
}

void* SVCEndpoint::svc_endpoint_reading_loop(void* args){
	SVCEndpoint* _this = (SVCEndpoint*)args;
	//-- read from unix socket then enqueue to incoming queue
	uint8_t buffer[SVC_DEFAULT_BUFSIZ]="";
	int readrs;
		
	while (_this->working){
		do{
			readrs = recv(_this->sock, buffer, SVC_DEFAULT_BUFSIZ, MSG_DONTWAIT);
		}
		while((readrs==-1) && _this->working);
		
		if (readrs>0){
			//printf("\nsvc endpoint read packet: %d: ", readrs); printBuffer(buffer, readrs); fflush(stdout);
			_this->incomingQueue.enqueue(new SVCPacket(buffer, readrs));			
		}
		//else: read received nothing
	}
	pthread_exit(EXIT_SUCCESS);
}

void* SVCEndpoint::svc_endpoint_writing_loop(void* args){
	SVCEndpoint* _this = (SVCEndpoint*)args;
	int sendrs;
	SVCPacket* packet;
	while (_this->working || _this->outgoingQueue.notEmpty() || _this->tobesentQueue.notEmpty()){
		packet = _this->tobesentQueue.dequeueWait(1000);		
		if (packet!=NULL){
			//-- send this packet to underlayer
			sendrs = send(_this->sock, packet->packet, packet->dataLen, 0);			
			delete packet;			
			//-- TODO: check this send result for futher decision
		}
	}
	pthread_exit(EXIT_SUCCESS);
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
	this->endpointSockPath = std::string(SVC_ENDPOINT_APP_PATH_PREFIX) + hexToString((uint8_t*)&this->endpointID, ENDPOINTID_LENGTH);	
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
		this->working = true;
		if (pthread_create(&this->readingThread, &attr, svc_endpoint_reading_loop, this) !=0){
			return -1;
		}		
		
		//-- create a packet handler to process incoming packets		
		this->incomingPacketHandler = new PacketHandler(&this->incomingQueue, svc_endpoint_incoming_packet_handler, this);
		return 0;
	}
}

int SVCEndpoint::connectToDaemon(){
	std::string endpointDmnSockPath = SVC_ENDPOINT_DMN_PATH_PREFIX + hexToString((uint8_t*)&this->endpointID, ENDPOINTID_LENGTH);
	struct sockaddr_un dmnEndpointAddr;
	memset(&dmnEndpointAddr, 0, sizeof(dmnEndpointAddr));
	dmnEndpointAddr.sun_family = AF_LOCAL;
	memcpy(dmnEndpointAddr.sun_path, endpointDmnSockPath.c_str(), endpointDmnSockPath.size());
	if (connect(this->sock, (struct sockaddr*)&dmnEndpointAddr, sizeof(dmnEndpointAddr)) != 0){
		return -1;
	}
	else{
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		if (pthread_create(&this->writingThread, &attr, svc_endpoint_writing_loop, this) !=0){
			this->writingThread = 0;
			return -1;
		}		
		else{
			//-- create a packet handler to process incoming packets		
			this->outgoingPacketHandler = new PacketHandler(&this->outgoingQueue, svc_endpoint_outgoing_packet_handler, this);		
			return 0;
		}
	}
}

bool SVCEndpoint::negotiate(){	
	
	uint8_t param[SVC_DEFAULT_BUFSIZ]="";
	uint16_t paramLen;
	SVCPacket* packet = new SVCPacket(this->endpointID);
	if (this->isInitiator){
		//--	send SVC_CMD_CONNECT_INNER1		
		packet->setCommand(SVC_CMD_CONNECT_INNER1);
		//-- get challenge secret and challenge		
		this->challengeSecretSent = this->svc->authenticator->generateChallengeSecret();		
		this->challengeSent = this->svc->authenticator->generateChallenge(challengeSecretSent);		
		packet->pushCommandParam((uint8_t*)challengeSent.c_str(), challengeSent.size());
		packet->pushCommandParam((uint8_t*)&this->svc->appID, APPID_LENGTH);
		packet->pushCommandParam((uint8_t*)challengeSecretSent.c_str(), challengeSecretSent.size());
		uint32_t remoteAddr = this->remoteHost->getHostAddress();
		packet->pushCommandParam((uint8_t*)&remoteAddr, HOST_ADDR_LENGTH);
		
		this->outgoingQueue.enqueue(packet);
		
		if (!this->incomingPacketHandler->waitCommand(SVC_CMD_CONNECT_INNER4, this->endpointID, SVC_DEFAULT_TIMEOUT)){
			this->isAuth = false;
		}
		else{
			if (!this->incomingPacketHandler->waitCommand(SVC_CMD_CONNECT_INNER6, this->endpointID, SVC_DEFAULT_TIMEOUT)){
				this->isAuth = false;
			}
		}
	}
	else{
		//-- read challenge from request packet
		this->request->popCommandParam(param, &paramLen);
		this->challengeReceived = std::string((char*)param, paramLen);		
		
		//-- resolve this challenge to get challenge secret
		this->challengeSecretReceived = this->svc->authenticator->resolveChallenge(this->challengeReceived);
		
		//-- generate proof
		this->proof = this->svc->authenticator->generateProof(this->challengeSecretReceived);		
		
		//-- generate challenge
		this->challengeSecretSent = this->svc->authenticator->generateChallengeSecret();		
		this->challengeSent = this->svc->authenticator->generateChallenge(this->challengeSecretSent);		
				
		packet->setCommand(SVC_CMD_CONNECT_INNER3);
		packet->pushCommandParam((uint8_t*)this->challengeSent.c_str(), this->challengeSent.size());
		packet->pushCommandParam((uint8_t*)this->proof.c_str(), this->proof.size());
		packet->pushCommandParam((uint8_t*)this->challengeSecretSent.c_str(), this->challengeSecretSent.size());
		packet->pushCommandParam((uint8_t*)this->challengeSecretReceived.c_str(),  this->challengeSecretReceived.size());
		
		this->outgoingQueue.enqueue(packet);
		if (!this->incomingPacketHandler->waitCommand(SVC_CMD_CONNECT_INNER8, this->endpointID, SVC_DEFAULT_TIMEOUT)){
			this->isAuth = false;
		}
	}	
	return this->isAuth;
}

void SVCEndpoint::shutdown(){
	if (this->working){
	
		//-- send a shutdown packet to daemon		
		SVCPacket* packet = new SVCPacket(this->endpointID);
		packet->setCommand(SVC_CMD_SHUTDOWN_ENDPOINT);
		this->outgoingQueue.enqueue(packet);
	
		this->working = false;
		int joinrs;
		//-- do not receive data anymore
		if (this->readingThread !=0) {
			joinrs = pthread_join(this->readingThread, NULL);
		}
		
		//-- process residual packets
		if (this->incomingPacketHandler != NULL){
			this->incomingPacketHandler->stopWorking();
			joinrs = this->incomingPacketHandler->waitStop();
			delete this->incomingPacketHandler;
		}
		
		//-- send out residual packets
		if (this->outgoingPacketHandler != NULL){
			this->outgoingPacketHandler->stopWorking();
			joinrs = this->outgoingPacketHandler->waitStop();			
			delete this->outgoingPacketHandler;
		}	
		
		//-- stop writing		
		if (this->writingThread !=0) {
			joinrs = pthread_join(this->writingThread, NULL);			
		}			
		unlink(this->endpointSockPath.c_str());
		
		//-- remove queues and created instances		
		if (this->request != NULL) delete this->request;
		
		//-- unregister from endpoints collection
		this->svc->endpoints[this->endpointID]= NULL;		
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
		this->outgoingQueue.enqueue(packet);
		return 0;
	}
	else{
		return -1;
	}
}

int SVCEndpoint::readData(uint8_t* data, uint32_t* len, int timeout){
	if (this->isAuth){
		SVCPacket* packet = this->dataholdQueue.dequeueWait(timeout);
		if (packet!=NULL){
			packet->extractData(data, len);
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

