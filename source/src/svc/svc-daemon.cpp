#include "svc-utils.h"
#include <cstdlib>
#include <netinet/in.h>
#include <unordered_map>
#include <unistd.h>
#include <sys/un.h>
#include <sys/stat.h>

#include "../crypto/crypto-utils.h"
#include "../crypto/AES256.h"
#include "../crypto/SHA256.h"
#include "../crypto/ECCurve.h"
#include "../crypto/AESGCM.h"


#define SVC_VERSION 0x01

using namespace std;

//--	class forward declaration
class DaemonEndpoint;

//--	GLOBAL VARIABLES
unordered_map<uint64_t, DaemonEndpoint*> endpoints;
struct sockaddr_un daemonSockUnAddress;
struct sockaddr_in daemonSockInAddress;
int daemonUnSocket;
int daemonInSocket;
PacketHandler* unPacketHandler;
PacketHandler* inPacketHandler;
PeriodicWorker* endpointChecker;
uint16_t daemonEndpointCounter = 0;

class DaemonEndpoint{
	public:
		//-- static methods
		static void dmn_endpoint_command_handler(SVCPacket* packet, void* args);
		
		//-- private members
		bool isAuth;
		int initLiveTime;
		int dmnSocket;
		string dmnSockPath;
		struct sockaddr_in remoteAddr;
		size_t remoteAddrLen;
		PacketHandler* packetHandler;
		//-- crypto protocol variables
		string encryptedECPoint;
		string encryptedProof;
		ECCurve* curve;
		ECPoint* gx;
		ECPoint* gy;
		ECPoint* gxy;
		AES256* aes256;
		SHA256* sha256;
		AESGCM* aesgcm;
		
		//-- constructors/destructors
		DaemonEndpoint(uint64_t endpointID);
		~DaemonEndpoint();
		
		//-- public members
		uint64_t endpointID;
		uint64_t sendSequence;
		uint64_t recvSequence;
		SharedMutex* sendSequenceMutex;
		SharedMutex* recvSequenceMutex;
					
		//-- public methods
		void sendPacketIn(SVCPacket* packet);
		void sendPacketOut(SVCPacket* packet);
		bool checkInitLiveTime(int interval);
		bool isAuthenticated();
		
		void encryptPacket(SVCPacket* packet);
		void decryptpacket(SVCPacket* packet);
		void connectToAddress(uint32_t remoteAddress);
		void connectToAddress(const struct sockaddr_in* sockAddr, socklen_t sockLen);
};

DaemonEndpoint::DaemonEndpoint(uint64_t endpointID){
	
	this->endpointID = endpointID;	
	this->isAuth = false;
	this->initLiveTime = SVC_ENDPOINT_LIVETIME;
	this->sendSequence = 0;
	this->recvSequence = 0;
	this->sendSequenceMutex = new SharedMutex();
	this->recvSequenceMutex = new SharedMutex();
	
	this->sha256 = new SHA256();
	
	//-- create dmn unix socket, bind 
	this->dmnSocket = socket(AF_LOCAL, SOCK_DGRAM, 0);
	struct sockaddr_un dmnSockAddr;
	this->dmnSockPath = SVC_ENDPOINT_DMN_PATH_PREFIX + hexToString((uint8_t*)&endpointID, ENDPOINTID_LENGTH);
	memset(&dmnSockAddr, 0, sizeof(dmnSockAddr));
	dmnSockAddr.sun_family = AF_LOCAL;
	memcpy(dmnSockAddr.sun_path, this->dmnSockPath.c_str(), dmnSockPath.size());
	bind(this->dmnSocket, (struct sockaddr*) &dmnSockAddr, sizeof(dmnSockAddr));
	printf("\ndaemon endpoint binded to: %s", dmnSockPath.c_str()); 
	//-- then connect to app socket
	struct sockaddr_un appSockAddr;
	string appSockPath = SVC_ENDPOINT_APP_PATH_PREFIX + hexToString((uint8_t*)&endpointID, ENDPOINTID_LENGTH);
	memset(&appSockAddr, 0, sizeof(appSockAddr));
	appSockAddr.sun_family = AF_LOCAL;
	memcpy(appSockAddr.sun_path, appSockPath.c_str(), appSockPath.size());
	connect(this->dmnSocket, (struct sockaddr*) &appSockAddr, sizeof(appSockAddr));
	printf("\ndaemon endpoint connected to: %s", appSockPath.c_str()); 
	//-- create a packet handler
	this->packetHandler = new PacketHandler(this->dmnSocket);
	this->packetHandler->setCommandHandler(dmn_endpoint_command_handler, this);

}

DaemonEndpoint::~DaemonEndpoint(){	
	delete this->packetHandler;
	unlink(this->dmnSockPath.c_str());
}

void DaemonEndpoint::connectToAddress(uint32_t remoteAddress){
	this->remoteAddrLen = sizeof(this->remoteAddr);							
	this->remoteAddr.sin_family = AF_INET;
	this->remoteAddr.sin_port = htons(SVC_DAEPORT);
	this->remoteAddr.sin_addr.s_addr = remoteAddress;
}

void DaemonEndpoint::connectToAddress(const struct sockaddr_in* sockAddr, socklen_t sockLen){
	memcpy(&this->remoteAddr, sockAddr, sockLen);
	this->remoteAddrLen = sockLen;
}

void DaemonEndpoint::sendPacketIn(SVCPacket* packet){
	this->packetHandler->sendPacket(packet);
}

void DaemonEndpoint::sendPacketOut(SVCPacket* packet){
	//add sequence number to packet
	this->sendSequenceMutex->lock();
	this->sendSequence += 1;
	memcpy(packet->packet + ENDPOINTID_LENGTH + 1, (uint8_t*)&this->sendSequence, SEQUENCE_LENGTH);
	int sendrs = sendto(daemonInSocket, packet->packet,packet->dataLen, 0, (struct sockaddr*)&this->remoteAddr, this->remoteAddrLen);
	this->sendSequenceMutex->unlock();
	//printf("\npacket sent %d: ", sendrs); printBuffer(packet->packet, packet->dataLen);
}

bool DaemonEndpoint::checkInitLiveTime(int interval){
	this->initLiveTime -= interval;
	return (this->initLiveTime>0);
}

bool DaemonEndpoint::isAuthenticated(){
	return this->isAuth;
}

//-- endpoint packet handling functions

void DaemonEndpoint::dmn_endpoint_command_handler(SVCPacket* packet, void* args){
	DaemonEndpoint* _this = (DaemonEndpoint*)args;
	enum SVCCommand cmd = (enum SVCCommand)packet->packet[SVC_PACKET_HEADER_LEN];
	
	uint8_t* param = param = (uint8_t*)malloc(SVC_DEFAULT_BUFSIZ);
	uint16_t paramLen;
	
	string hashValue;
	uint8_t* aeskey;
	AES256* aes256 = NULL;
	int requested_security_strength;
	mpz_t randomNumber;
	
	char* ecpointHexString;
	uint16_t ecpointHexLen;
	
	string solutionProof;
	uint64_t sequence;
	
	uint8_t* encrypted;
	uint32_t encryptedLen;
	uint8_t* tag;
	uint32_t tagLen;
	
	uint8_t* data;
	uint32_t dataLen;
	
	
	switch (cmd){
		case SVC_CMD_CONNECT_INNER1:
			if (!_this->isAuth){
				//printf("\nreceived packet: "); printBuffer(packet->packet, packet->dataLen);
				//printf("\nCONNECT_INNER1 received");			
				//-- extract remote address
				packet->popCommandParam(param, &paramLen);		
				_this->connectToAddress(*((uint32_t*)param));			
				//-- extract challengeSecret x
				packet->popCommandParam(param, &paramLen);
				//-- use SHA256(x) as an AES256 key
				hashValue = _this->sha256->hash(string((char*)param, paramLen));
				stringToHex(hashValue, &aeskey); //AES key is guaranteed to be 256 bits length
				if (aes256!=NULL) delete aes256;
				aes256 = new AES256(aeskey);
				//-- generate STS-gx
				if (_this->curve == NULL) _this->curve = new ECCurve();
				requested_security_strength = _this->curve->getRequestSecurityLength();
				mpz_init(randomNumber);
				generateRandomNumber(&randomNumber, requested_security_strength);
				_this->gx = _this->curve->mul(_this->curve->g, &randomNumber);
				
				paramLen = 0;
				//-- use created AES to encrypt gx = Ex(gx), copy to param
				ecpointHexString = mpz_get_str(NULL, 16, _this->gx->x);
				ecpointHexLen = strlen(ecpointHexString) + 1;			
				printf("\nsent gx_x: %s", ecpointHexString); fflush(stdout);				
				memcpy(param + paramLen, &ecpointHexLen, 2);
				paramLen += 2;
				memcpy(param + paramLen, ecpointHexString, ecpointHexLen);	
				paramLen += ecpointHexLen;
				delete ecpointHexString;
				
				ecpointHexString = mpz_get_str(NULL, 16, _this->gx->y);
				ecpointHexLen = strlen(ecpointHexString)+1; 
				printf("\nsent gx_y: %s", ecpointHexString); fflush(stdout);
				memcpy(param + paramLen, &ecpointHexLen, 2);
				paramLen += 2;				
				memcpy(param+paramLen, ecpointHexString, ecpointHexLen);
				paramLen += ecpointHexLen;				
				//printf("\nsent gxx || gxy: "); printBuffer(param, paramLen); fflush(stdout);
				delete ecpointHexString;				
				
				aes256->encrypt(param, paramLen, &encrypted, &encryptedLen);
				
				//-- attach Ex(k1) to packet
				packet->pushCommandParam(encrypted, encryptedLen);
				delete encrypted;
				
				//-- switch commandID
				packet->switchCommand(SVC_CMD_CONNECT_OUTER1);
				//-- sent the packet
				_this->sendPacketOut(packet);
			}
			//delete packet;
			break;
			
		case SVC_CMD_CONNECT_INNER3:
			packet->popCommandParam(param, &paramLen);
			//-- use SHA256(x) as an AES256 key
			hashValue = _this->sha256->hash(string((char*)param, paramLen));
			stringToHex(hashValue, &aeskey); //-- aes key used to decrypt k1
			aes256 = new AES256(aeskey);
			delete aeskey;
			aes256->decrypt((uint8_t*)_this->encryptedECPoint.c_str(), _this->encryptedECPoint.size(), &data, &dataLen);
			//-- construct gx from decrypted K1
			//printf("\nreceived gxx || gxy: "); printBuffer(data, dataLen); fflush(stdout);
			paramLen = *((uint16_t*)data);
			printf("\nreceived gx_x: %s", data + 2);
			//printf("\ngx_y by printBuffer: "); printBuffer(data + 4 + paramLen, dataLen - 4 - paramLen); fflush(stdout);
			printf("\nreceived gx_y: %s", data + 4 + paramLen); fflush(stdout);
			_this->gx = new ECPoint((char*)(data + 2) , (char*)(data + 4 + paramLen));
			delete data;
			
			//-- extract challengeSecret y
			packet->popCommandParam(param, &paramLen);
			//-- use SHA256(y) as an AES256 key
			hashValue = _this->sha256->hash(string((char*)param, paramLen));
						
			//-- create new aes key to encrypt
			stringToHex(hashValue, &aeskey);
			delete aes256;
			aes256 = new AES256(aeskey);
			delete aeskey;
			
			//-- generate STS-gy
			if (_this->curve == NULL) _this->curve = new ECCurve();
			requested_security_strength = _this->curve->getRequestSecurityLength();
			mpz_init(randomNumber);
			generateRandomNumber(&randomNumber, requested_security_strength);
			_this->gy = _this->curve->mul(_this->curve->g, &randomNumber);
			
			//-- generate shared secret gxy
			_this->gxy = _this->curve->mul(_this->gx, &randomNumber);
			ecpointHexString = mpz_get_str(NULL, 16, _this->gxy->x);
			ecpointHexLen = strlen(ecpointHexString);
			memcpy(param, ecpointHexString, ecpointHexLen);			
			delete ecpointHexString;
			
			ecpointHexString = mpz_get_str(NULL, 16, _this->gxy->x);
			memcpy(param + paramLen , ecpointHexString, strlen(ecpointHexString));
			paramLen += strlen(ecpointHexString);
			delete ecpointHexString;
			if (_this->aesgcm == NULL){
				//-- aesgcm key = hash(gxy.x || gxy.y)
				hashValue = _this->sha256->hash(string((char*)param, paramLen));
				stringToHex(hashValue, &aeskey);
				_this->aesgcm = new AESGCM(aeskey, (enum SecurityParameter)requested_security_strength);
			}
			
			//-- pop solution proof to be encrypted
			packet->popCommandParam(param, &paramLen);
			solutionProof = string((char*)param, paramLen);
			
			//-- use created AES to encrypt gy = Ey(gy), copy to param
			ecpointHexString = mpz_get_str(NULL, 16, _this->gy->x);
			ecpointHexLen = strlen(ecpointHexString) + 1;
			printf("\nsent gy_x: %s", ecpointHexString);
			paramLen = 0;
			memcpy(param + paramLen, &ecpointHexLen, 2);
			paramLen += 2;
			memcpy(param + paramLen, ecpointHexString, ecpointHexLen);
			paramLen += ecpointHexLen;
			
			ecpointHexString = mpz_get_str(NULL, 16, _this->gy->y);
			ecpointHexLen = strlen(ecpointHexString) + 1;
			printf("\nsent gy_y: %s", ecpointHexString);
			memcpy(param + paramLen, &ecpointHexLen, 2);
			paramLen += 2;
			memcpy(param+paramLen, ecpointHexString, ecpointHexLen);
			paramLen += ecpointHexLen;
			aes256->encrypt(param, paramLen, &encrypted, &encryptedLen);
				
			//-- switch command
			packet->switchCommand(SVC_CMD_CONNECT_OUTER2);
			//-- attach Ey(gy) to packet
			packet->pushCommandParam(encrypted, encryptedLen);
			delete encrypted;			
			
			//-- encrypt solution proof then attach to packet
			//-- get current sendSequence to be iv
			_this->sendSequenceMutex->lock_shared();
			sequence = _this->sendSequence;
			_this->sendSequenceMutex->unlock_shared();
			_this->aesgcm->encrypt((uint8_t*)&sequence, SEQUENCE_LENGTH, (uint8_t*)solutionProof.c_str(), solutionProof.size(), NULL, 0, &encrypted, &encryptedLen, &tag, &tagLen);
			//-- add encrypted and tag to param
			paramLen = 0;
			memcpy(param + paramLen, &encryptedLen, 2);
			paramLen += 2;
			memcpy(param + paramLen, encrypted, encryptedLen);
			paramLen += encryptedLen;
			memcpy(param + paramLen, &tagLen, 2);
			paramLen += 2;
			memcpy(param + paramLen, tag, tagLen);
			paramLen += tagLen;			
			packet->pushCommandParam(param, paramLen);
			delete encrypted;
			delete tag;
			
			//-- send out this packet
			_this->sendPacketOut(packet);
			//delete packet;
			break;
			
		case SVC_CMD_CONNECT_OUTER2:
			//printf("\nSVC_CMD_CONNECT_OUTER2 received");
			//printf("\npacket: "); printBuffer(packet->packet, packet->dataLen); 
			//-- pop encrypted proof
			packet->popCommandParam(param, &paramLen);
			_this->encryptedProof = string((char*)param, paramLen);
			//printf("\npacket: "); printBuffer(packet->packet, packet->dataLen);
			packet->popCommandParam(param, &paramLen);
			_this->encryptedECPoint = string((char*)param, paramLen);
			//printf("\npacket: "); printBuffer(packet->packet, packet->dataLen); 
			//-- change command to INNER_4
			packet->switchCommand(SVC_CMD_CONNECT_INNER4);
			//-- app svc is still waiting for the 'old' endpointID, push the current endpointID as new param
			packet->pushCommandParam(packet->packet, ENDPOINTID_LENGTH);
			//-- clear the 6&7 byte of endpointID
			packet->packet[6]=0x00;
			packet->packet[7]=0x00;
			_this->sendPacketIn(packet);
			//printf("\npacket: "); printBuffer(packet->packet, packet->dataLen); 
			fflush(stdout);
			//delete packet; //-- ERROR here!!!
			break;
			
		case SVC_CMD_CONNECT_INNER5:
			printf("\nSVC_CMD_CONNECT_INNER5 received");
			
		default:
			break;
	}
	//delete packet;
	delete param;
}

void signal_handler(int sig){
	//printf("\ncaptured signal: %d", sig);
	if (sig == SIGINT){
		printf("\nSIGINT caught, stopping daemon...");
		//--	request all endpoint to stop working
		for (auto& it : endpoints){
			if (it.second != NULL){
				DaemonEndpoint* ep = (DaemonEndpoint*)it.second;
				it.second = NULL;
				delete ep;
			}
		}
		//--	stop main threads
		inPacketHandler->stopWorking();
		unPacketHandler->stopWorking();	
		endpointChecker->stopWorking();
		//--	do cleanup before exit
		unlink(SVC_DAEMON_PATH.c_str());
	}	
}

/*
 * daemon command handler
 * */
 
void sendPacketToApp(SVCPacket* packet){
	//send
}
 
void daemonUnCommandHandler(SVCPacket* packet, void* args){
	//printf("\ndaemon un received command: "); fflush(stdout); printBuffer(packet, packetLen);
	enum SVCCommand cmd = (enum SVCCommand)packet->packet[SVC_PACKET_HEADER_LEN];
	uint64_t endpointID = *((uint64_t*)packet->packet);
	switch (cmd){
		case SVC_CMD_CREATE_ENDPOINT:
			//-- check if the endpoint already exists
			if (endpoints[endpointID]==NULL){
				DaemonEndpoint* endpoint = new DaemonEndpoint(endpointID);				
				endpoints[endpointID] = endpoint;
				//-- send back the packet
				endpoint->sendPacketIn(packet);
			}
			else{
				delete packet;
			}
			break;
		default:
			delete packet;
			break;
	}
}

void daemonInCommandHandler(SVCPacket* packet, void* args){
	enum SVCCommand cmd = (enum SVCCommand)packet->packet[SVC_PACKET_HEADER_LEN];
	uint64_t endpointID = *((uint64_t*)packet->packet);
	uint64_t newEndpointID = 0;
	uint8_t* param = (uint8_t*)malloc(SVC_DEFAULT_BUFSIZ);
	uint16_t paramLen;
	uint32_t appID;
	string appSockPath;
	DaemonEndpoint* dmnEndpoint;
	
	struct sockaddr_in sourceAddr;
	socklen_t sourceAddrLen;
	struct sockaddr_un appSockAddr;	
	memset(&appSockAddr, 0, sizeof(appSockAddr));
	appSockAddr.sun_family = AF_LOCAL;
	int sendrs;
	
	switch (cmd){
		case SVC_CMD_CONNECT_OUTER1:
			newEndpointID |= ++daemonEndpointCounter;
			newEndpointID <<= 48;
			newEndpointID |= endpointID;
			//-- create new daemonEndpoint for this endpointID
			dmnEndpoint = new DaemonEndpoint(newEndpointID);
			printf("\nendpoint created with iD: "); printBuffer((uint8_t*)&newEndpointID, ENDPOINTID_LENGTH);
			endpoints[newEndpointID] = dmnEndpoint;
			//-- extract source address
			packet->popCommandParam(param, &paramLen);
			memcpy(&sourceAddr, param, paramLen);
			sourceAddrLen = paramLen;
			dmnEndpoint->connectToAddress(&sourceAddr, sourceAddrLen);
			//-- extract DH-1
			packet->popCommandParam(param, &paramLen);
			dmnEndpoint->encryptedECPoint = string((char*)param, paramLen);
			//-- extract appID
			packet->popCommandParam(param, &paramLen);
			//-- send the packet to the corresponding app
			packet->switchCommand(SVC_CMD_CONNECT_INNER2);			
			appID = *((uint32_t*)param);
			appSockPath = SVC_CLIENT_PATH_PREFIX + to_string(appID);			
			memcpy(appSockAddr.sun_path, appSockPath.c_str(), appSockPath.size());
			//-- replace the oldEndpointID by the newEndpointID
			memcpy(packet->packet, (uint8_t*)&newEndpointID, ENDPOINTID_LENGTH);
			sendrs = sendto(daemonUnSocket, packet->packet, packet->dataLen, 0, (struct sockaddr*)&appSockAddr, sizeof(appSockAddr));			
			delete packet;
			break;
		case SVC_CMD_CONNECT_OUTER2:
			//printf("\nSVC_CMD_CONNECT_OUTER2 received");
			//printf("\nreceived endpointID: "); printBuffer((uint8_t*)&endpointID, ENDPOINTID_LENGTH);
			//-- newEndpointID contains old ID			
			newEndpointID = endpointID;
			endpointID = newEndpointID & 0x0000FFFFFFFFFFFF;
			//printf("\nOld endpointID: "); printBuffer((uint8_t*)&endpointID, ENDPOINTID_LENGTH); fflush(stdout);
			if (endpoints[endpointID] != NULL){
				//printf("endpoint found"); fflush(stdout);
				endpoints[newEndpointID] = endpoints[endpointID];
				endpoints[endpointID] = NULL;
				//--	update endpointID
				endpoints[newEndpointID]->endpointID = newEndpointID;
				//-- forward packet
				DaemonEndpoint::dmn_endpoint_command_handler(packet, endpoints[newEndpointID]);
			}
		default:			
			if (endpoints[endpointID] != NULL){
				//-- forward packet if endpoint found
				DaemonEndpoint::dmn_endpoint_command_handler(packet, endpoints[newEndpointID]);
			}
			else{
				//-- drop packet
				delete packet;
			}
			break;
	}
	
	delete param;
}

void checkEndpointLiveTime(void* args){
	for (auto& it : endpoints){
		if (it.second != NULL){
			DaemonEndpoint* ep = (DaemonEndpoint*)it.second;
			if (!(ep->isAuthenticated() || ep->checkInitLiveTime(1000))){
				//remove this endpoint, also remove it from endpoints
				endpoints[ep->endpointID] = NULL;
				delete ep;
			}
		}
	}
}

int main(int argc, char** argv){
	
	string errorString;

	//--	create a daemon unix socket and bind
	daemonUnSocket = socket(AF_LOCAL, SOCK_DGRAM, 0);
	memset(&daemonSockUnAddress, 0, sizeof(daemonSockUnAddress));
	daemonSockUnAddress.sun_family = AF_LOCAL;
	memcpy(daemonSockUnAddress.sun_path, SVC_DAEMON_PATH.c_str(), SVC_DAEMON_PATH.size());			
	if (bind(daemonUnSocket, (struct sockaddr*) &daemonSockUnAddress, sizeof(daemonSockUnAddress)) == -1) {		
		errorString = SVC_ERROR_BINDING;
        goto errorInit;
    }    
    
    //--TODO:	TO BE CHANGED TO HTP
    //--	create htp socket and bind to localhost
    daemonInSocket = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&daemonSockInAddress, 0, sizeof(daemonSockInAddress));
    daemonSockInAddress.sin_family = AF_INET;
    daemonSockInAddress.sin_port = htons(SVC_DAEPORT);
	daemonSockInAddress.sin_addr.s_addr = htonl(INADDR_ANY);      
    if (bind(daemonInSocket, (struct sockaddr*) &daemonSockInAddress, sizeof(daemonSockInAddress))){
    	errorString = SVC_ERROR_BINDING;
    	goto errorInit;
    }
    
    //-- block some signals
    sigset_t blockSignals;
    sigemptyset(&blockSignals);
    sigaddset(&blockSignals, SVC_ACQUIRED_SIGNAL);
    sigaddset(&blockSignals, SVC_SHARED_MUTEX_SIGNAL);
    sigaddset(&blockSignals, SVC_PERIODIC_SIGNAL);
    sigaddset(&blockSignals, SVC_TIMEOUT_SIGNAL);
    pthread_sigmask(SIG_BLOCK, &blockSignals, NULL);
    
    //-- handle SIGINT
	struct sigaction act;
	act.sa_handler = signal_handler;
	sigfillset(&act.sa_mask);
	sigdelset(&act.sa_mask, SIGINT);
	sigaction(SIGINT, &act, NULL);
	
    //--	create a thread to read from unix domain socket
    unPacketHandler = new PacketHandler(daemonUnSocket);
    unPacketHandler->setDataHandler(NULL, NULL);
    unPacketHandler->setCommandHandler(daemonUnCommandHandler, NULL);
    
	//--	create a thread to read from htp socket
	inPacketHandler = new PacketHandler(daemonInSocket);
	inPacketHandler->setDataHandler(NULL, NULL);
	inPacketHandler->setCommandHandler(daemonInCommandHandler, NULL);
	
	//--	create a thread to check for daemon endpoints' lives
	endpointChecker = new PeriodicWorker(1000, checkEndpointLiveTime, NULL);
	
	//--	init some globals variables
	
    goto initSuccess;
    
    errorInit:
    	printf("\nError: %s\n", errorString.c_str());
    	exit(EXIT_FAILURE);
    	
    initSuccess:
		//--	POST-SUCCESS JOBS	--//
    	printf("\nSVC daemon is running...");
    	fflush(stdout);
        inPacketHandler->waitStop();
    	unPacketHandler->waitStop();
    	endpointChecker->waitStop();
    	delete inPacketHandler;
    	delete unPacketHandler;
    	delete endpointChecker;
    	printf("\nSVC daemon stopped\n");
}


