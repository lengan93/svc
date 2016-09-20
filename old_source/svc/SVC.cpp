#include "SVC.h"

//---for debugging, to be removed
#include <iostream>
#include <errno.h>


//--	SVC IMPLEMENTATION	//
SVC::SVC(SVCApp* localApp, SVCAuthenticator* authenticator){
	
	const char* errorString;
	
	this->localApp = localApp;
	this->authenticator = authenticator;
	
	endPointsMutex = new shared_mutex();
	
	//--	check for existed socket
	this->appID = (uint32_t)hasher(localApp->getAppID());
	this->svcClientPath = SVC_CLIENT_PATH_PREFIX + to_string(appID);	
	if (unlink(this->svcClientPath.c_str())==0){
		errorString = SVC_ERROR_NAME_EXISTED;
		goto errorInit;
	}
		
	//--	daemon's endpoint to write to
	memset(&this->daemonSocketAddress, 0, sizeof(this->daemonSocketAddress));
	this->daemonSocketAddress.sun_family = AF_LOCAL;
	memcpy(this->daemonSocketAddress.sun_path, SVC_DAEMON_PATH.c_str(), SVC_DAEMON_PATH.size());
	this->svcDaemonSocket = socket(AF_LOCAL, SOCK_DGRAM, 0);
	connect(this->svcDaemonSocket, (struct sockaddr*) &this->daemonSocketAddress, sizeof(this->daemonSocketAddress));
	
	//--	svc's endpoint to read from
	memset(&this->svcSocketAddress, 0, sizeof(this->svcSocketAddress));
	this->svcSocketAddress.sun_family = AF_LOCAL;
	memcpy(this->svcSocketAddress.sun_path, this->svcClientPath.c_str(), this->svcClientPath.size());
	this->svcSocket = socket(AF_LOCAL, SOCK_DGRAM, 0);	
	if (bind(this->svcSocket, (struct sockaddr*)&this->svcSocketAddress, sizeof(this->svcSocketAddress))==-1){
		errorString = SVC_ERROR_BINDING;
		goto errorInit;	
	}
	
	this->connectionRequest = new MutexedQueue<Message*>();
	
	//--	create reading thread	
	sigset_t sig;
	sigfillset(&sig);
	sigaddset(&sig, SIGUSR2);
	sigaddset(&sig, SIGUSR1);
	if (pthread_sigmask(SIG_BLOCK, &sig, NULL)!=0){
		errorString = SVC_ERROR_CRITICAL;
		goto errorInit;
	}		
	this->working = true;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_create(&this->readingThread, &attr, processPacket, this);
	
	goto success;
	
	errorInit:
		//destruct params manually
		this->destruct();
		throw errorString;
		
	success:
		printf("\nsvc created");
}

void SVC::destruct(){
	this->working = false;	
	pthread_join(this->readingThread, NULL);
	
	//--	remove remaining endpoints
	this->endPointsMutex->lock();
	for (SVCEndPoint* endPoint : this->endPoints){
		if (endPoint!=NULL){
			delete endPoint;
		}
	}
	this->endPoints.clear();
	this->endPointsMutex->unlock();
	
	unlink(this->svcClientPath.c_str());
	printf("\nsvc destructed");
}

void SVC::stopWorking(){
	this->working = false;
}

SVCEndPoint* SVC::getEndPointByID(uint64_t endPointID){
	this->endPointsMutex->lock_shared();
	for (SVCEndPoint* endPoint : this->endPoints){
		if (endPoint!=NULL){
			if (endPoint->endPointID == endPointID){
				this->endPointsMutex->unlock_shared();
				return endPoint;
			}
		}
	}
	this->endPointsMutex->unlock_shared();
	return NULL;
}

SVC::~SVC(){
	this->destruct();
}

/* SVC PRIVATE FUNCTION IMPLEMENTATION	*/

void* SVC::processPacket(void* args){

	SVC* _this = (SVC*)args;
		
	int byteRead;
	uint8_t* buffer = (uint8_t*)malloc(SVC_DEFAULT_BUFSIZ);

	uint64_t endPointID;	
	vector<SVCCommandParam*> params;
	SVCEndPoint* endPoint;
	
	while (_this->working){
		do{
			byteRead = recv(_this->svcSocket, buffer, SVC_DEFAULT_BUFSIZ, MSG_DONTWAIT);		
		}
		while((byteRead==-1) && _this->working);
		
		if (byteRead>0){
			printf("\nread a packet: ");
			printBuffer(buffer, byteRead);
			
			endPointID = *((uint64_t*)buffer);
			uint8_t infoByte = buffer[ENDPOINTID_LENGTH];
			
			_this->endPointsMutex->lock_shared();
			endPoint = _this->getEndPointByID(endPointID);
			_this->endPointsMutex->unlock_shared();
		
			if (infoByte & SVC_COMMAND_FRAME){				
				extractParams(buffer + ENDPOINTID_LENGTH + 2, &params);
				
				enum SVCCommand cmd = (enum SVCCommand)buffer[ENDPOINTID_LENGTH + 1];
				
				if (endPoint==NULL){
					if (cmd == SVC_CMD_CONNECT_STEP1){
						//--	add this to connection request
						printf("\nadd SVC_CMD_CONNECT_STEP1 to queue");
						_this->connectionRequest->enqueue(new Message(buffer, byteRead));					
					}
					//--	else: other commands not allows without endPoint
				}
				else{
					//--	notify the corresponding endPoint
					SVCDataReceiveNotificator* notificator = endPoint->signalNotificator->getNotificator(cmd);
					if (notificator!=NULL){
						notificator->handler(buffer, byteRead, notificator);
						endPoint->signalNotificator->removeNotificator(cmd);
					}
				}				
			}
			else{
				if (endPoint!=NULL){
					//--	forward to dataQueue
					endPoint->dataQueue->enqueue(new Message(buffer, byteRead));
				}
				//--	else: no data allowed without endPoint				
			}
		}
	}
	
	free(buffer);
	printf("\nsvc process packet stopped");
}

/*void* SVC::processConnectionRequest(void* args){
	
}*/

/*	SVC PUBLIC FUNCTION IMPLEMENTATION	*/

SVCEndPoint* SVC::establishConnection(SVCHost* remoteHost){
	
	SVCEndPoint* rs = NULL;
	SVCEndPoint* endPoint;
	SignalNotificator* sigNot;		
	vector<SVCCommandParam*> params;
	
	sigNot = new SignalNotificator();
	srand(time(NULL));
	uint64_t endPointID = (uint64_t)hasher(this->localApp->getAppID()+to_string(rand()));	
	endPoint = new SVCEndPoint(this, sigNot);
	endPoint->setEndPointID(endPointID);
	
	endPointsMutex->lock();
	endPoints.push_back(endPoint);
	endPointsMutex->unlock();

	//--	authentication variables
	string identity;
	string challengeSent;
	string challengeReceived;
	string proof;
	
	//--	send establishing request to the daemon with appropriate params			
	
	challengeSent = this->authenticator->generateChallenge();
	uint32_t serverAddress  = remoteHost->getHostAddress();
	uint32_t appID = (uint32_t)hasher(this->localApp->getAppID());
	clearParams(&params);
	params.push_back(new SVCCommandParam(challengeSent.size(), (uint8_t*)challengeSent.c_str()));
	params.push_back(new SVCCommandParam(4, (uint8_t*) &appID));
	params.push_back(new SVCCommandParam(4, (uint8_t*) &serverAddress));
	endPoint->sendCommand(SVC_CMD_CONNECT_STEP1, &params);
	
	printf("\nSVC_CMD_CONNECT_STEP1 sent");
	//--	wait for SVC_CMD_CONNECT_STEP2, identity + proof + challenge, respectively. keyexchange is retained at daemon level.
	if (sigNot->waitCommand(SVC_CMD_CONNECT_STEP2, &params, SVC_DEFAULT_TIMEOUT)){
		printf("\nSVC_CMD_CONNECT_STEP2 received");
		//--	get identity, proof, challenge
		/*for (int i=0; i<=2; i++){
			printf("params[%d]: ", i);printBuffer(params[i]->data, params[i]->len);
		}*/
		char ch[SVC_DEFAULT_BUFSIZ] = "";
		memcpy(ch, params[0]->data, params[0]->len);
		identity = string(ch);
		memset(ch, 0, SVC_DEFAULT_BUFSIZ);
		
		memcpy(ch, params[1]->data, params[1]->len);
		proof = string(ch);
		memset(ch, 0, SVC_DEFAULT_BUFSIZ);
		
		memcpy(ch, params[2]->data, params[2]->len);
		challengeReceived = string(ch);
		memset(ch, 0, SVC_DEFAULT_BUFSIZ);
		
		printf("\nget identity: %s\n proof: %s\n challenge: %s", identity.c_str(), proof.c_str(), challengeReceived.c_str());
		
		//--	verify server's identity
		if (this->authenticator->verifyIdentity(identity, challengeSent, proof)){
			//--	ok, server's identity verified. request daemon to perform keyexchange. the daemon responds the success of encrypting process
			printf("\nserver's identity verified\n");
			clearParams(&params);			
			endPoint->sendCommand(SVC_CMD_CONNECT_STEP3, &params);
			printf("\nsend SVC_CMD_CONNECT_STEP3 to daemon\n");
			//--	wait for daemon. if the connection to this address is already secured, it will return shortly
			if (sigNot->waitCommand(SVC_CMD_CONNECT_STEP3, &params, SVC_DEFAULT_TIMEOUT)){
				printf("\nSVC_CMD_CONNECT_STEP3 received from daemon");
				//a.3 perform SVC_CMD_CONNECT_STEP4, send identity + proof
				clearParams(&params);
				identity = this->authenticator->getIdentity();
				proof = this->authenticator->generateProof(challengeReceived);
				params.push_back(new SVCCommandParam(identity.size(), (uint8_t*)identity.c_str()));
				params.push_back(new SVCCommandParam(proof.size(), (uint8_t*)proof.c_str()));
				endPoint->sendCommand(SVC_CMD_CONNECT_STEP4, &params);
				printf("\nsend CONNECT_STEP4 with client's identity: %s\nproof: %s", identity.c_str(), proof.c_str());
				rs = endPoint;
			}
			/*
			else: no response from daemon, error occured or timeout
			*/								
		}
		/*
		else: server identity verification failed, exception
		*/
	}
	/*
	else: time out
	*/
	if (rs == NULL){
		delete sigNot;
		delete endPoint;
	}
	return rs;
}


SVCEndPoint* SVC::listenConnection(){
	
	vector<SVCCommandParam*> params;
	SVCEndPoint* rs = NULL;
	SVCEndPoint* endPoint;
	Message* message;
	uint64_t endPointID;
	SignalNotificator* sigNot;

	//--	authentication variablees	
	string identity;
	string challengeSent;
	string challengeReceived;
	string proof;
	
	sigNot = new SignalNotificator();
	endPoint = new SVCEndPoint(this, sigNot);
	
	endPointsMutex->lock();
	endPoints.push_back(endPoint);
	endPointsMutex->unlock();
	
	message = this->connectionRequest->dequeueWait();

	//--TODO: detach a new thread to do this - should or should not?
	if (message!=NULL){
		//--	process this connection request, this is a SVC_CMD_CONNECT_STEP1		
		clearParams(&params);
		extractParams(message->data + ENDPOINTID_LENGTH + 2, &params);
				
		endPointID = *((uint64_t*)(message->data));
		endPoint->endPointID = endPointID;
		printf("\nendPointID: "); printBuffer((uint8_t*) &endPointID, 8);
		//--	read the challenge
		char ch[SVC_DEFAULT_BUFSIZ] = "";
		memcpy(ch, (char*)(params[0]->data), params[0]->len);
		challengeReceived = string(ch);
		proof = this->authenticator->generateProof(challengeReceived);
		identity = this->authenticator->getIdentity();
		challengeSent = this->authenticator->generateChallenge();
	
		printf("\nchallenge received: %s\n", challengeReceived.c_str());
		//--	send response
		clearParams(&params);
		params.push_back(new SVCCommandParam(identity.size(), (uint8_t*)identity.c_str()));
		params.push_back(new SVCCommandParam(proof.size(), (uint8_t*)proof.c_str()));
		params.push_back(new SVCCommandParam(challengeSent.size(), (uint8_t*)challengeSent.c_str()));
		endPoint->sendCommand(SVC_CMD_CONNECT_STEP2, &params);
		printf("\nsend CONNECT_STEP2 with:\nidentity:%s\nproof:%s\nchallenge:%s", identity.c_str(), proof.c_str(), challengeSent.c_str());
		
		//--	wait for SVC_CMD_CONNECT_STEP4, step3 is handled by the daemon		
		if (sigNot->waitCommand(SVC_CMD_CONNECT_STEP4, &params, SVC_DEFAULT_TIMEOUT)){
			//--	read identity + proof
			memset(ch, 0, SVC_DEFAULT_BUFSIZ);
			memcpy(ch, (char*)(params[0]->data), params[0]->len);
			identity = string(ch);
			
			memset(ch, 0, SVC_DEFAULT_BUFSIZ);
			memcpy(ch, (char*)(params[1]->data), params[1]->len);
			proof = string(ch);
			
			printf("\ngot CONNECT_STEP4 with:\nidentity:%s\nproof:%s", identity.c_str(), proof.c_str());
	
			//--	verify client's identity
			if (this->authenticator->verifyIdentity(identity, challengeSent, proof)){
				printf("client's identity verified!\n");
				//--	tell the daemon endpoint
				clearParams(&params);
				endPoint->sendCommand(SVC_CMD_CONNECT_CLIENT_VERIFIED, &params);
				rs = endPoint;
			}
		}
	}
	else{
		//--	dequeueWait == NULL means it is interrupted by SIGINT
		throw SVC_ERROR_SIGNAL_INTERRUPTED;
	}
	if (rs == NULL){
		delete sigNot;
		delete endPoint;
	}
	return rs;
}


//--	SVCENDPOINT class	//



SVCEndPoint::SVCEndPoint(SVC* svc, SignalNotificator* sigNot){
	this->svc = svc;
	this->signalNotificator = sigNot;
	this->dataQueue = new MutexedQueue<Message*>();
};

void SVCEndPoint::setEndPointID(uint64_t endPointID){
	this->endPointID = endPointID;
	//--	create new un socket to write to
	/*this->endPointSocket = sock(AF_LOCAL, SOCK_DGRAM, 0);

	memset(&this->daemonSocketAddress, 0, sizeof(this->daemonSocketAddress));
	this->daemonSocketAddress.sun_family = AF_LOCAL;
	memcpy(this->daemonSocketAddress.sun_path, SVC_DAEMON_PATH.c_str(), SVC_DAEMON_PATH.size());
	this->svcDaemonSocket = socket(AF_LOCAL, SOCK_DGRAM, 0);
	connect(this->svcDaemonSocket, (struct sockaddr*) &this->daemonSocketAddress, sizeof(this->daemonSocketAddress));*/
}

void SVCEndPoint::sendCommand(enum SVCCommand cmd, vector<SVCCommandParam*>* params){				

	uint8_t* buffer = (uint8_t*)malloc(SVC_DEFAULT_BUFSIZ);
	int pointer = 0;
	size_t bufferLength = ENDPOINTID_LENGTH + 3;	//endpointid + info + cmd + argc

	for (int i=0; i<params->size(); i++){
		//--	2 bytes for param length, then the param itself
		bufferLength += 2 + (*params)[i]->len;
	}								
			
	//--	ADD HEADER	--//				
	//--	endPointID
	memcpy(buffer + pointer, (uint8_t*) &this->endPointID, ENDPOINTID_LENGTH);
	pointer += ENDPOINTID_LENGTH;
	//--	info byte				
	buffer[pointer] = 0x00;
	buffer[pointer] = buffer[pointer] | SVC_COMMAND_FRAME;
	buffer[pointer] = buffer[pointer] | SVC_URGENT_PRIORITY; 	//commands are always urgent
	buffer[pointer] = buffer[pointer] | SVC_USING_TCP; 			//to ensure the delivery of commands				
	if (isEncryptedCommand(cmd)) buffer[pointer] = buffer[pointer] | SVC_ENCRYPTED;
	pointer += 1;
	//--	1 byte command ID				
	buffer[pointer] = cmd;
	pointer += 1;				
	//--	1 byte param length				
	buffer[pointer] = params->size();
	pointer += 1;
	
	//--	ADD PARAMS	--//
	for (int i=0; i<params->size(); i++){					
		memcpy(buffer + pointer, (uint8_t*) &((*params)[i]->len), 2);
		memcpy(buffer + pointer + 2, (*params)[i]->data, (*params)[i]->len);
		pointer += 2 + (*params)[i]->len;
	}
	
	//--	SEND	--//
	send(this->svc->svcDaemonSocket, buffer, bufferLength, 0);
	printf("\nendpoint send: ");
	printBuffer(buffer, bufferLength);
	//--	free params
	clearParams(params);
}

SVCEndPoint::~SVCEndPoint(){
	delete this->dataQueue;
	printf("\nend point "); printBuffer((uint8_t*) &this->endPointID, 8);printf(" destructed");
}

int SVCEndPoint::sendData(const uint8_t* data, size_t dalalen, uint8_t priority, bool tcp){
}

int SVCEndPoint::readData(uint8_t* data, size_t* len){
}

