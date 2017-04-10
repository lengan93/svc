#include "SVC.h"
//--debug header, to be removed
#include "iostream"
using namespace std;

//--	SVC		//
SVC::SVC(const std::string& appIdentity, SVCAuthenticator* authenticator){

	std::string err;
	SHA256 sha256;
	uint8_t appIdentityHashed[SHA256::DIGEST_SIZE];
	sha256.hash((uint8_t*)appIdentity.c_str(), appIdentity.size(), appIdentityHashed);
	this->appID = *((uint32_t*)(appIdentityHashed));
	this->authenticator = authenticator;

	//-- create svc pipe
	this->svcPipe = NamedPipe::createUniqueNamedPipe(SVC_PIPE_PREFIX, &this->pipeID);

	//-- connect to daemon pipe, throwable ERR_NOT_CONNECTED
	this->daemonPipe = new NamedPipe(SVC_PIPE_PREFIX + SVC_DEFAULT_DAEMON_NAME, NamedPipeMode::NP_WRITE);

	//-- create reading thread to read from pipe
	this->incomingQueue = new MutexedQueue<SVCPacket*>();
	this->packetReader = new SVCPacketReader(this->svcPipe, this->incomingQueue, 0);
	//-- create thread to handler incoming packet
	this->packetHandler = new SVCPacketHandler(this->incomingQueue, svc_incoming_packet_handler, this);
	
	//-- create queue to hold incoming request
	this->connectionRequests = new MutexedQueue<SVCPacket*>();
	
	//-- send SVC_CMD_REGISTER
	SVCPacket* packet = new SVCPacket();
	packet->setEndpointID(this->pipeID);
	packet->setCommand(SVC_CMD_REGISTER_SVC);
	packet->pushDataChunk(&this->appID, APPID_LENGTH);

	uint8_t* waitCommandData = NULL;
	uint8_t buffer[SVC_DEFAULT_BUFSIZ];
	uint16_t packetLen;
	packet->serialize(buffer, &packetLen);
	delete packet;
	// cout<<"sending:";
	// printHexBuffer(buffer, packetLen);
	if (this->daemonPipe->write(buffer, packetLen, 0) < 0){
		err = ERR_NOT_CONNECTED;
		goto error_shutdown;
	}

	if (!this->packetHandler->waitCommand(SVC_CMD_REGISTER_SVC, this->pipeID, -1, &waitCommandData)){
		// cout<<"waitCommand failed"<<endl;
		err = ERR_TIMEOUT;
		goto error_shutdown;
	}
	else{
		//-- extract config from data
	}

	goto success_return;

	error_shutdown:
		this->shutdown();
		throw err;
	
	success_return:
		this->working = true;
		// cout<<"svc create success"<<endl;
}

void SVC::shutdown(){
	if (this->working){
		this->working = false;

		cout<<"send SVC_CMD_SHUTDOWN_SVC"<<endl;
		uint8_t buffer[SVC_DEFAULT_BUFSIZ];
		uint16_t bufferLen;

		SVCPacket* packet = new SVCPacket();
		packet->setEndpointID(this->pipeID);
		packet->setCommand(SVC_CMD_SHUTDOWN_SVC);
		packet->serialize(buffer, &bufferLen);
		this->daemonPipe->write(buffer, bufferLen, 0);
		delete packet;

		this->daemonPipe->close();
		this->svcPipe->close();
		this->packetReader->stopWorking();
		this->incomingQueue->close();
		this->packetHandler->stopWorking();
		this->connectionRequests->close();

		//-- clean up
		delete this->packetReader;
		delete this->svcPipe;
		delete this->daemonPipe;
		delete this->packetHandler;
		delete this->incomingQueue;
		delete this->connectionRequests;
	}
}

SVC::~SVC(){
	this->shutdown();
}

void SVC::svc_incoming_packet_handler(SVCPacket* packet, void* args){	
	SVC* _this = (SVC*)args;
	uint8_t infoByte = packet->getInfoByte();

	if ((infoByte & SVC_COMMAND_FRAME) != 0x00){
		//-- incoming command
		enum SVCCommand cmd = (enum SVCCommand)packet->getExtraInfoByte();
		uint64_t endpointID = packet->getEndpointID();
		switch(cmd){
			case SVC_CMD_REGISTER_SVC:
				break;

			case SVC_CMD_DAEMON_DOWN:
				//-- daemon fatal error and need to shutdown, end all pending operations
				_this->shutdown();
				break;

			case SVC_CMD_CONNECT_INNER2:
				_this->connectionRequests->enqueue(new SVCPacket(packet));
				break;

			default:	
				break;
		}
		if (_this->packetHandler != NULL){
			_this->packetHandler->notifyCommand(cmd, endpointID, NULL);
		}
		else{
			delete packet;
		}
	}
	else{
		//-- svc doesn't allow data
		delete packet;
	}	
}

SVCEndpoint* SVC::establishConnection(const std::string& remoteHost, uint8_t option){
	
	SVCEndpoint* endpoint;

	//-- create a unique named pipe
	uint64_t endpointPipeID;
	NamedPipe* endpointNamedPipe = NamedPipe::createUniqueNamedPipe(SVC_ENDPOINT_PIPE_PREFIX, &endpointPipeID);

	//-- send SVC_CMD_CREATE_ENDPOINT to daemon
	uint8_t buffer[SVC_DEFAULT_BUFSIZ];
	uint16_t bufferLen;

	SVCPacket* packet = new SVCPacket();
	packet->setEndpointID(this->pipeID);
	packet->setCommand(SVC_CMD_CREATE_ENDPOINT);
	
	packet->pushDataChunk(remoteHost.c_str(), remoteHost.length());
	packet->pushDataChunk(&endpointPipeID, ENDPOINTID_LENGTH);
	packet->pushDataChunk(&option, 1);
	packet->serialize(buffer, &bufferLen);
	this->daemonPipe->write(buffer, bufferLen, 0);
	delete packet;

	cout<<"wait for SVC_CMD_CREATE_ENDPOINT"<<endl;
	uint8_t* result;
	if (!this->packetHandler->waitCommand(SVC_CMD_CREATE_ENDPOINT, this->pipeID, -1, &result)){
		delete endpointNamedPipe;
	}
	else{
		cout<<"received SVC_CMD_CREATE_ENDPOINT"<<endl;
		//-- response received, extract param from packet
		if (*result == SVC_SUCCESS){
			endpoint = new SVCEndpoint(this, true, endpointNamedPipe, endpointPipeID);
		}
	}
	return endpoint;
}

SVCEndpoint* SVC::listenConnection(const std::string& remoteHost, uint8_t option){
	SVCPacket* request;
	request = this->connectionRequests->dequeueWait(-1);
	if (request != NULL){
		//-- TODO: compare remoteHost vs request->senderAddr, if conform
		if (true){
			uint64_t pipeID = request->getEndpointID();
			//-- create reading pipe for new endpoint
			try{
				NamedPipe* readingPipe = new NamedPipe(SVC_ENDPOINT_PIPE_PREFIX + to_string(pipeID), NamedPipeMode::NP_READ);
				SVCEndpoint* endpoint = new SVCEndpoint(this, false, readingPipe, pipeID);
				endpoint->requestPacket = request;
				return endpoint;
			}
			catch(std::string& e){
				delete request;
				return NULL;
			}
		}
		else{
			delete request;
			return NULL;
		}
	}
	else{
		return NULL;
	}
}

//--	SVCENDPOINT		//
SVCEndpoint::SVCEndpoint(SVC* svc, bool isInitiator, NamedPipe* readingPipe, uint64_t pipeID){
	this->svc = svc;
	this->isInitiator = isInitiator;
	this->pipeID = pipeID;
	this->readingPipe = readingPipe;
	this->writingPipe = new NamedPipe(SVC_DAEMON_ENDPOINT_PIPE_PREFIX + to_string(this->pipeID), NamedPipeMode::NP_WRITE);
	this->incomingQueue = new MutexedQueue<SVCPacket*>();
	this->dataHoldQueue = new MutexedQueue<SVCPacket*>();
	this->packetReader = new SVCPacketReader(this->readingPipe, this->incomingQueue, 0);
	this->packetHandler = new SVCPacketHandler(this->incomingQueue, SVCEndpoint::incoming_packet_handler, this);
	this->working = true;
};

void SVCEndpoint::incoming_packet_handler(SVCPacket* packet, void* args){
	delete packet;
	SVCEndpoint* _this = (SVCEndpoint*)args;

	uint8_t param[SVC_DEFAULT_BUFSIZ];
	uint16_t paramLen;
	
	uint8_t infoByte = packet->getInfoByte();
	if ((infoByte & SVC_COMMAND_FRAME) != 0x00){
		SVCCommand cmd = (SVCCommand)packet->getExtraInfoByte();
		uint64_t endpointID = packet->getEndpointID();
		
		switch (cmd){
				
			case SVC_CMD_SHUTDOWN_ENDPOINT:
				{
					_this->stopWorking(false);
				}
				break;

			case SVC_CMD_CONNECT_INNER2:
				{
					printf("\nreceived SVC_CMD_CONNECT_INNER2");
					packet->popDataChunk(param, &paramLen);
					_this->challengeSet.challengeReceived = std::string((char*)param, paramLen);
					_this->challengeSet.challengeSecretReceived = _this->svc->authenticator->resolveChallenge(_this->challengeSet.challengeReceived);
					_this->challengeSet.proofSent =  _this->svc->authenticator->generateProof(_this->challengeSet.challengeSecretReceived);
					_this->challengeSet.challengeSecretSent = _this->svc->authenticator->generateChallengeSecret();
					_this->challengeSet.challengeSent = _this->svc->authenticator->generateChallenge(_this->challengeSet.challengeSecretSent);

					packet->setCommand(SVC_CMD_CONNECT_INNER3);
					packet->pushDataChunk(_this->challengeSet.challengeSent.c_str(), _this->challengeSet.challengeSent.size());
					packet->pushDataChunk(_this->challengeSet.proofSent.c_str(), _this->challengeSet.proofSent.size());
					packet->serialize(param, &paramLen);
					_this->writingPipe->write(param, paramLen, 0);
				}
				break;
							
			case SVC_CMD_CONNECT_INNER4:
				{
					printf("\nreceived SVC_CMD_CONNECT_INNER4");
					packet->popDataChunk(param, &paramLen);
					_this->challengeSet.challengeReceived = std::string((char*)param, paramLen);
					
					//--	resolve challenge then send back to daemon
					_this->challengeSet.challengeSecretReceived = _this->svc->authenticator->resolveChallenge(_this->challengeSet.challengeReceived);
					
					packet->setCommand(SVC_CMD_CONNECT_INNER5);				
					packet->pushDataChunk(_this->challengeSet.challengeSecretReceived.c_str(), _this->challengeSet.challengeSecretReceived.size());
					packet->serialize(param, &paramLen);
					_this->writingPipe->write(param, paramLen, 0);
					_this->packetHandler->notifyCommand(cmd, endpointID, NULL);
				}
				break;
				
			case SVC_CMD_CONNECT_INNER6:
				{
					printf("\nreceived SVC_CMD_CONNECT_INNER6");
					//-- verify the client's proof
					uint8_t connectSuccess;
					packet->popDataChunk(param, &paramLen);
					_this->challengeSet.proofReceived = std::string((char*)param, paramLen);
					if (_this->svc->authenticator->verifyProof(_this->challengeSet.challengeSecretSent, _this->challengeSet.proofReceived)){
						//-- send confirm to daemon
						packet->setCommand(SVC_CMD_CONNECT_INNER7);
						packet->serialize(param, &paramLen);
						_this->writingPipe->write(param, paramLen, 0);
						//-- proof verification succeeded
						connectSuccess = SVC_SUCCESS;
					}
					else{
						//-- proof verification failed
						connectSuccess = SVC_FAILED;
					}
					_this->packetHandler->notifyCommand(cmd, endpointID, &connectSuccess);
				}
				break;
				
			default:
				break;
			
			delete packet;
		}
	}
	else{
		_this->dataHoldQueue->enqueue(packet);
	}
}

bool SVCEndpoint::negotiate(int timeout){
	uint8_t buffer[SVC_DEFAULT_BUFSIZ];
	uint16_t bufferLen;

	bool negotiationResult = false;

	SVCPacket* packet = new SVCPacket();
	packet->setEndpointID(this->pipeID);
	if (this->isInitiator){
		packet->setCommand(SVC_CMD_CONNECT_INNER1);
		//-- get challenge secret and challenge		
		this->challengeSet.challengeSecretSent = this->svc->authenticator->generateChallengeSecret();		
		this->challengeSet.challengeSent = this->svc->authenticator->generateChallenge(this->challengeSet.challengeSecretSent);		
		packet->pushDataChunk(this->challengeSet.challengeSent.c_str(), this->challengeSet.challengeSent.size());
		packet->serialize(buffer, &bufferLen);
		this->writingPipe->write(buffer, bufferLen, 0);
		delete packet;

		uint8_t* result;
		if (this->packetHandler->waitCommand(SVC_CMD_CONNECT_INNER4, this->pipeID, timeout, &result)){
			negotiationResult = *result == SVC_SUCCESS;
		}
		else{
			negotiationResult = false;
		}
	}
	else{
		//-- read challenge from request packet
		this->requestPacket->popDataChunk(buffer, &bufferLen);
		this->challengeSet.challengeReceived = std::string((char*)buffer, bufferLen);
	
		//-- resolve this challenge to get challenge secret
		this->challengeSet.challengeSecretReceived = this->svc->authenticator->resolveChallenge(this->challengeSet.challengeReceived);
		//this->remoteIdentity = this->svc->authenticator->getRemoteIdentity(this->challengeSecretReceived);
		//-- generate proof
		this->challengeSet.proofSent = this->svc->authenticator->generateProof(this->challengeSet.challengeSecretReceived);		
	
		//-- generate challenge
		this->challengeSet.challengeSecretSent = this->svc->authenticator->generateChallengeSecret();		
		this->challengeSet.challengeSent = this->svc->authenticator->generateChallenge(this->challengeSet.challengeSecretSent);		
		
		packet->setCommand(SVC_CMD_CONNECT_INNER3);
		packet->pushDataChunk(this->challengeSet.challengeSent.c_str(), this->challengeSet.challengeSent.size());
		packet->pushDataChunk(this->challengeSet.proofSent.c_str(), this->challengeSet.proofSent.size());
		packet->serialize(buffer, &bufferLen);
		this->writingPipe->write(buffer, bufferLen, 0);
		delete packet;

		uint8_t* result;
		if (this->packetHandler->waitCommand(SVC_CMD_CONNECT_INNER6, this->pipeID, timeout, &result)){
			negotiationResult = *result == SVC_SUCCESS;
		}
		else{
			negotiationResult = false;
		}
	}
	return negotiationResult;
}

void SVCEndpoint::stopWorking(bool isInitiator){
	if (this->working){
		this->working = false;

		uint8_t buffer[SVC_DEFAULT_BUFSIZ];
		uint16_t bufferLen;

		if (isInitiator){
			SVCPacket* packet = new SVCPacket();
			packet->setEndpointID(this->pipeID);
			packet->setCommand(SVC_CMD_SHUTDOWN_ENDPOINT);
			packet->serialize(buffer, &bufferLen);
			this->writingPipe->write(buffer, bufferLen, 0);
		}

		this->isAuth = false;

		this->readingPipe->close();
		this->packetReader->stopWorking();
		this->incomingQueue->close();
		this->packetHandler->stopWorking();
		this->dataHoldQueue->close();
		this->writingPipe->close();

		//-- clean up
		delete this->readingPipe;
		delete this->writingPipe;
		delete this->packetReader;
		delete this->packetHandler;
		delete this->incomingQueue;
		delete this->dataHoldQueue;
	}
}

void SVCEndpoint::shutdown(){
	this->stopWorking(true);
}

SVCEndpoint::~SVCEndpoint(){	
	this->shutdown();
}

ssize_t SVCEndpoint::write(const uint8_t* buffer, uint16_t bufferLen, uint8_t option){
	if (this->isAuth){

		SVCPacket* packet = new SVCPacket();
		packet->setEndpointID(this->pipeID);
		packet->setExtraInfoByte(option);
		packet->pushDataChunk(buffer, bufferLen);

		uint8_t buf[SVC_DEFAULT_BUFSIZ];
		uint16_t bufLen;
		packet->serialize(buf, &bufLen);
		bufLen = this->writingPipe->write(buf, bufLen, 0);
		if (bufLen > bufferLen){
			return bufferLen;
		}
		else{
			return -1;
		}
	}
	else{
		return -1;
	}
}

ssize_t SVCEndpoint::read(uint8_t* buffer, uint16_t bufferLen, uint8_t option){
	if (this->isAuth){
		SVCPacket* packet = this->dataHoldQueue->dequeueWait(-1);
		if (packet!=NULL){
			uint16_t bufLen;
			uint8_t buf[SVC_DEFAULT_BUFSIZ];
			packet->popDataChunk(buf, &bufLen);
			if (bufLen > bufferLen){
				bufLen = bufferLen;
			}
			memcpy(buffer, buf, bufLen);
			delete packet;
			return bufLen;
		}
		else{
			//-- dequeueWait -1 return NULL, termination occurred
			return -1;
		}
	}
	else{
		return -1;
	}
}

