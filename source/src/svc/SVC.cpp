#include "SVC.h"

using namespace svc_utils::SVCPacket;

SVC::SVC(const std::string& appIdentity, const SVCAuthenticator* authenticator){

	SHA256 sha256;
	string appIDHashed = sha256->hash(appID);
	stringToHex(appIDHashed.substr(0, 8), (uint8_t*)&this->appID);
	this->authenticator = authenticator;

	//-- create svc pipe
	char buffer[32];
	utils::generateRandomData(32, buffer);
	string svcPipeName = sha256.hash(string(buffer));
	cout<<"create svc pipe named: "<<svcPipeName<<endl;
	this->svcPipe = new NamedPipe(svcPipeName, NamedPipe::NP_READ);

	//-- connect to daemon pipe
	this->daemonPipe = new NamedPipe(SVC_DEFAULT_DAEMON_NAME, NamedPipe::NP_WRITE);

	//-- create reading thread to read from pipe
	this->incomingQueue = new MutexedQueue<SVCPacket*>();
	this->packetReader = new SVCPacketReader(this->daemonPipe, this->incomingQueue);

	//-- create thread to handler incoming packet
	this->packetHandler = new SVCPacketHandler(this->incomingQueue, svc_incoming_packet_handler, this);
	
	//-- send SVC_CMD_REGISTER
	SVCPacket* packet = new SVCPacket(0);
	packet->setCommand(SVC_CMD_REGISTER);
	packet->pushCommandParam(svcPipename.c_str(), svcPipeName.size());
	if (this->daemonPipe->write(packet->packet, packet->dataLen)) < 0){
		throw ERR_NOT_CONNECTED;
	}
	delete packet;
	this->packetHandler->waitCommand();
	if (!this->packetHandler->waitCommand()){
		throw ERR_TIMEOUT;
	}

	this->connectionRequests = new MutexedQueue<SVCPacket*>();
	this->endpoints.clear();
}

void SVC::shutdown(){

	if (!this->shutdownCalled){
		printf("\nSVC shutdown called"); fflush(stdout);
		this->shutdownCalled = true;
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
		printf("\ncall shutdown socket"); fflush(stdout);
		shutdown(this->appSocket, SHUT_RD);

		printf("\ncall join"); fflush(stdout);
		if (this->readingThread !=0) pthread_join(this->readingThread, NULL);
		
		delete this->incomingPacketHandler;
			
		//-- stop writing packets
		shutdown(this->appSocket, SHUT_WR);	
		close(this->appSocket);
		
		printf("\nremove queues"); fflush(stdout);
		//-- remove queues and intances
		delete this->connectionRequests;
		delete this->sha256;	
		printf("\nsvc destructed"); fflush(stdout);	
	}
}

SVC::~SVC(){
	shutdownSVC();
}

void SVC::svc_incoming_packet_handler(SVCPacket* packet, void* args){
	SVC* _this = (SVC*)args;
	
	uint8_t infoByte = packet->packet[INFO_BYTE];

	if ((infoByte & SVC_COMMAND_FRAME) != 0x00){
		//-- incoming command
		enum SVCCommand cmd = (enum SVCCommand)packet->packet[CMD_BYTE];
		uint64_t endpointID = *((uint64_t*)(packet->packet+1));
		switch(cmd){
		
			case SVC_CMD_CONNECT_INNER2:
				_this->connectionRequests->enqueue(packet);
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




//--	SVC PUBLIC FUNCTION IMPLEMENTATION		--//

void SVC::sendPacketToDaemon(SVCPacket* packet){
	send(this->appSocket, packet->packet, packet->dataLen, 0);
}

SVCEndpoint* SVC::establishConnection(int timeout, SVCHost* remoteHost, uint8_t option){
	
	//-- create new endpoint to handle further packets
	uint64_t endpointID = 0;	
	endpointID |= ++SVC::endpointCounter;
	endpointID<<=32;
	endpointID |= this->appID;
	try{
		SVCEndpoint* endpoint = new SVCEndpoint(this, endpointID, true);
		endpoint->sockOption = option;
		endpoint->setRemoteHost(remoteHost);
		//-- add this endpoint to be handled
		this->endpoints[endpoint->endpointID] = endpoint;
		
		//-- send SVC_CMD_CREATE_ENDPOINT to daemon
		SVCPacket* packet = new SVCPacket(endpoint->endpointID);
		packet->setCommand(SVC_CMD_CREATE_ENDPOINT);
		packet->pushCommandParam(&option, 1);
		sendPacketToDaemon(packet);
		
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
	catch(...){
		return NULL;
	}
}

SVCEndpoint* SVC::listenConnection(int timeout){
	SVCPacket* request;
	request=this->connectionRequests->dequeueWait(timeout);
	if (request!=NULL){
		//-- there is connection request, read for endpointID
		uint64_t endpointID = *((uint64_t*)(request->packet+1));
		SVCEndpoint* ep;
		try{
			ep = new SVCEndpoint(this, endpointID, false);
			ep->request = request;		
			if (ep->connectToDaemon() == 0){
				this->endpoints[endpointID] = ep;
				return ep;
			}
			else{				
				delete ep;
				return NULL;
			}
		}
		catch(...){		
			return NULL;
		}
	}
	else{
		return NULL;
	}
}
//--	SVCENDPOINT class	//

SVCEndpoint::SVCEndpoint(SVC* svc, uint64_t endpointID,  bool isInitiator){
	this->svc = svc;
	this->isInitiator = isInitiator;
	this->request = NULL;
	this->incomingPacketHandler = NULL;

	this->periodicWorker = NULL;
	this->readingThread = 0;
	this->writingThread = 0;
	this->shutdownCalled = false;
	this->reconnectFailed = false;
	this->reconnectionTimeout = RECONNECTION_TIMEOUT;
	
	this->endpointID = endpointID;	
	this->sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	
	string endpointSockPath = std::string(SVC_ENDPOINT_APP_PATH_PREFIX) + hexToString((uint8_t*)&this->endpointID, ENDPOINTID_LENGTH);	
	struct sockaddr_un sockAddr;
	memset(&sockAddr, 0, sizeof(sockAddr));
	sockAddr.sun_family = AF_LOCAL;
	sockAddr.sun_path[0]='\0';
	memcpy(sockAddr.sun_path+1, endpointSockPath.c_str(), endpointSockPath.size());
	
	if (bind(this->sock, (struct sockaddr*)&sockAddr, sizeof(sockAddr)) == -1){
		throw SVC_ERROR_BINDING;
	}
	else{
		//-- create new reading thread
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		this->working = true;
		if (pthread_create(&this->readingThread, &attr, svc_endpoint_reading_loop, this) !=0){
			throw SVC_ERROR_CRITICAL;
		}		
		//-- create a packet handler to process incoming packets
		this->tobesentQueue = new MutexedQueue<SVCPacket*>();
		this->dataholdQueue = new MutexedQueue<SVCPacket*>();		
		this->incomingPacketHandler = new PacketHandler();
	}
};

void SVCEndpoint::svc_endpoint_incoming_packet_handler(SVCPacket* packet, void* args){
	SVCEndpoint* _this = (SVCEndpoint*)args;

	uint8_t param[SVC_DEFAULT_BUFSIZ]="";
	uint16_t paramLen;
	
	uint8_t infoByte = packet->packet[INFO_BYTE];

	if ((infoByte & SVC_COMMAND_FRAME) != 0x00){
		//-- process incoming command
		SVCCommand cmd = (SVCCommand)packet->packet[CMD_BYTE];
		uint64_t endpointID = *((uint64_t*)(packet->packet+1));
		
		switch (cmd){
		
			case SVC_CMD_DAEMON_RESTART:
				if (packet->popCommandParam(param, &paramLen)){
					_this->daemonRestartReason = string((char*)param, paramLen);
				}
				delete packet;	
				break;
			
			case SVC_CMD_SHUTDOWN_ENDPOINT:
				delete packet;
				//printf("\ndaemon endpoint send shutdown cmd"); fflush(stdout);
				_this->isAuth = false;
				_this->working = false;
				break;
						
			case SVC_CMD_CONNECT_INNER4:				
				//--	new endpointID
				packet->popCommandParam(param, &paramLen);
				_this->changeEndpointID(*((uint64_t*)param));
				//-- replace packet endpointID with the new one
				memcpy(packet->packet+1, param, ENDPOINTID_LENGTH);		
				packet->popCommandParam(param, &paramLen);
				_this->challengeReceived = std::string((char*)param, paramLen);
				
				//--	resolve challenge then send back to daemon
				_this->challengeSecretReceived = _this->svc->authenticator->resolveChallenge(_this->challengeReceived);
				
				//- packet updated with new endpointID
				packet->switchCommand(SVC_CMD_CONNECT_INNER5);				
				packet->pushCommandParam((uint8_t*)_this->challengeSecretReceived.c_str(), _this->challengeSecretReceived.size());
				_this->tobesentQueue->enqueue(packet);
				break;
				
			case SVC_CMD_CONNECT_INNER6:								
				//-- pop solution proof and check
				packet->popCommandParam(param, &paramLen);
				if (_this->svc->authenticator->verifyProof(_this->challengeSecretSent, std::string((char*)param, paramLen))){
					//-- proof verified, generate proof then send back to daemon
					_this->proof = _this->svc->authenticator->generateProof(_this->challengeSecretReceived);
					packet->switchCommand(SVC_CMD_CONNECT_INNER7);				
					packet->pushCommandParam((uint8_t*)_this->proof.c_str(), _this->proof.size());
					
					_this->tobesentQueue->enqueue(packet);
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
					
					_this->tobesentQueue->enqueue(packet);
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
		_this->dataholdQueue->enqueue(packet);
	}
}


void* SVCEndpoint::svc_endpoint_reading_loop(void* args){
	SVCEndpoint* _this = (SVCEndpoint*)args;
	//-- read from unix socket then enqueue to incoming queue
	uint8_t buffer[SVC_DEFAULT_BUFSIZ]="";
	int readrs;
		
	while (_this->working){
		readrs = recv(_this->sock, buffer, SVC_DEFAULT_BUFSIZ, 0);
		if (readrs>0){
			//printf("\nsvc endpoint read packet: %d: ", readrs); printBuffer(buffer, readrs); fflush(stdout);
			svc_endpoint_incoming_packet_handler(new SVCPacket(buffer, readrs), _this);
		}
		//else: read received nothing
	}
	pthread_exit(EXIT_SUCCESS);
}

void* SVCEndpoint::svc_endpoint_writing_loop(void* args){
	SVCEndpoint* _this = (SVCEndpoint*)args;
	int sendrs;
	SVCPacket* packet;
	while (_this->working /*|| _this->outgoingQueue.notEmpty()*/ || _this->tobesentQueue->notEmpty()){
		if (_this->tobesentQueue->peakWait(&packet, -1)){		
			//-- send this packet to underlayer
			sendrs = send(_this->sock, packet->packet, packet->dataLen, 0);
			//printf("\nsvc endpoint write packet %d, error %d:  ", sendrs, errno); printBuffer(packet->packet, packet->dataLen); fflush(stdout);
			if (sendrs == -1 && !_this->reconnectFailed && !_this->shutdownCalled){
				if (errno == EPIPE || errno == ECONNREFUSED || errno == ENOTCONN){
					//-- call reconnection method
					string reason;
					if (_this->reconnectDaemon()){
						//-- TODO: log reason
					}
					else{
						//-- reconnection failed, shutdown
						_this->working = false;
						_this->isAuth = false;
						_this->reconnectFailed = true;
					}
				}
				else{
					//-- packet send failed with undefined error, TODO: log
					delete packet;
					_this->tobesentQueue->dequeue();
				}
			}
			else{
				//-- TODO: if log file declared then log these data
				delete packet;
				_this->tobesentQueue->dequeue();
			}
		}
	}
	pthread_exit(EXIT_SUCCESS);
}

void SVCEndpoint::setReconnectionTimeout(int timeout){
	if (timeout>0){
		this->reconnectionTimeout = timeout;
	}
}

bool SVCEndpoint::reconnectDaemon(){
	
	//printf("\nreconnectDaemon called"); fflush(stdout);
	std::string endpointDmnSockPath = SVC_ENDPOINT_DMN_PATH_PREFIX + hexToString((uint8_t*)&this->endpointID, ENDPOINTID_LENGTH);
	struct sockaddr_un dmnEndpointAddr;
	memset(&dmnEndpointAddr, 0, sizeof(dmnEndpointAddr));
	dmnEndpointAddr.sun_family = AF_LOCAL;
	dmnEndpointAddr.sun_path[0]= '\0';
	memcpy(dmnEndpointAddr.sun_path+1, endpointDmnSockPath.c_str(), endpointDmnSockPath.size());
	
	//-- connect wait for SVC_CMD_DAEMON_RESTART
	int timeout = this->reconnectionTimeout;
	int connectResult = -1;
	do{
		//printf("\ntry wait SVC_CMD_DAEMON_RESTART 1000"); fflush(stdout);
		if (connectResult == -1) connectResult = connect(this->sock, (struct sockaddr*)&dmnEndpointAddr, sizeof(dmnEndpointAddr));
		if (this->incomingPacketHandler->waitCommand(SVC_CMD_DAEMON_RESTART, this->endpointID, 1000)){
			return true;
		}
		else{
			timeout-=1000;
		}
	}
	while(timeout>0 && !this->shutdownCalled);
	
	return false;
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

void SVCEndpoint::liveCheck(void* args){
	SVCEndpoint* _this = (SVCEndpoint*)args;
	
	if (_this->working){
		SVCPacket* packet = new SVCPacket(_this->endpointID);
		packet->setCommand(SVC_CMD_CHECK_ALIVE);
		_this->tobesentQueue->enqueue(packet);
	}	
}

int SVCEndpoint::connectToDaemon(){
	std::string endpointDmnSockPath = SVC_ENDPOINT_DMN_PATH_PREFIX + hexToString((uint8_t*)&this->endpointID, ENDPOINTID_LENGTH);
	struct sockaddr_un dmnEndpointAddr;
	memset(&dmnEndpointAddr, 0, sizeof(dmnEndpointAddr));
	dmnEndpointAddr.sun_family = AF_LOCAL;
	dmnEndpointAddr.sun_path[0]= '\0';
	memcpy(dmnEndpointAddr.sun_path+1, endpointDmnSockPath.c_str(), endpointDmnSockPath.size());
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
			//-- create a periodic worker to send beat to daemon endpoint
			this->periodicWorker = new PeriodicWorker(1000, liveCheck, this);
			return 0;
		}
	}
}

string SVCEndpoint::getEndpointID(){
	return this->endpointID;
}

bool SVCEndpoint::negotiate(){
	
	uint8_t* param = (uint8_t*)malloc(SVC_DEFAULT_BUFSIZ);
	uint16_t paramLen;
	SVCPacket* packet;
	
	if (this->working){
		this->isAuth = false;
		packet = new SVCPacket(this->endpointID);
		if (this->isInitiator){
			//--	send SVC_CMD_CONNECT_INNER1		
			packet->setCommand(SVC_CMD_CONNECT_INNER1);
			//-- get challenge secret and challenge		
			this->challengeSecretSent = this->svc->authenticator->generateChallengeSecret();		
			this->challengeSent = this->svc->authenticator->generateChallenge(challengeSecretSent);		
			packet->pushCommandParam((uint8_t*)challengeSent.c_str(), challengeSent.size());
			packet->pushCommandParam((uint8_t*)this->remoteHost->getAppID().c_str(), APPID_LENGTH);
			packet->pushCommandParam((uint8_t*)challengeSecretSent.c_str(), challengeSecretSent.size());
			uint32_t remoteAddr = this->remoteHost->getHostAddress();
			packet->pushCommandParam((uint8_t*)&remoteAddr, HOST_ADDR_LENGTH);
		
			this->tobesentQueue->enqueue(packet);
		
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
			this->remoteIdentity = this->svc->authenticator->getRemoteIdentity(this->challengeSecretReceived);
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
			this->tobesentQueue->enqueue(packet);
			
			if (!this->incomingPacketHandler->waitCommand(SVC_CMD_CONNECT_INNER8, this->endpointID, SVC_DEFAULT_TIMEOUT)){
				this->isAuth = false;
			}
		}
		free(param);
		return this->isAuth;
	}
	else{
		free(param);
		return false;
	}
}

std::string SVCEndpoint::getRemoteIdentity(){
	return this->remoteIdentity;
}

void SVCEndpoint::shutdownEndpoint(){
	if (!this->shutdownCalled){
		printf("\nendpoint shutdown called"); fflush(stdout);
		this->shutdownCalled = true;
		//-- send a shutdown packet to daemon
		SVCPacket* packet = new SVCPacket(this->endpointID);
		packet->setCommand(SVC_CMD_SHUTDOWN_ENDPOINT);
		this->tobesentQueue->enqueue(packet);

		this->working = false;
		this->isAuth = false;
		int joinrs;
		
		//-- stop sending beat
		if (this->periodicWorker !=NULL){
			this->periodicWorker->stopWorking();
			this->periodicWorker->waitStop();
			delete this->periodicWorker;
		}
		
		//-- do not receive data anymore
		shutdown(this->sock, SHUT_RD);
		if (this->readingThread !=0) {
			joinrs = pthread_join(this->readingThread, NULL);
		}
	
		//-- process residual packets
		if (this->incomingPacketHandler != NULL){
			this->incomingPacketHandler->stopWorking();
			joinrs = this->incomingPacketHandler->waitStop();
			delete this->incomingPacketHandler;
		}
		
		//-- stop writing
		shutdown(this->sock, SHUT_WR);
		if (this->writingThread !=0) {
			joinrs = pthread_join(this->writingThread, NULL);			
		}			
		close(this->sock);
	
		//-- remove queues and created instances		
		if (this->request != NULL) delete this->request;
	
		//-- unregister from endpoints collection
		this->svc->endpoints[this->endpointID]= NULL;
		
		delete this->tobesentQueue;
		delete this->dataholdQueue;
		
		printf("\nendpoint removed"); fflush(stdout);
	}
}

SVCEndpoint::~SVCEndpoint(){	
	this->shutdownEndpoint();
}

int SVCEndpoint::sendData(const uint8_t* data, uint32_t dataLen){
	if (this->isAuth){
		//-- try to send		
		SVCPacket* packet = new SVCPacket(this->endpointID);
		packet->setData(data, dataLen);
		this->tobesentQueue->enqueue(packet);
		return 0;
	}
	else{
		return -1;
	}
}

int SVCEndpoint::readData(uint8_t* data, uint32_t* len, int timeout){
	if (this->isAuth){
		SVCPacket* packet = this->dataholdQueue->dequeueWait(timeout);
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

