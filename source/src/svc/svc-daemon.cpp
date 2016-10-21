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
		static void dmn_endpoint_inner_command_handler(SVCPacket* packet, void* args);
	
		//-- private members
		bool isAuth;
		int initLiveTime;
		int dmnSocket;
		string dmnSockPath;
		struct sockaddr_in remoteAddr;
		size_t remoteAddrLen;
		PacketHandler* packetHandler;
		//-- crypto protocol variables
		string challengeSecret;
		ECCurve* curve;
		ECPoint* gx;
		ECPoint* gy;
		ECPoint* gxy;
		AES256* aes256;
		SHA256* sha256;
		
		//-- constructors/destructors
		DaemonEndpoint(uint64_t endpointID);
		~DaemonEndpoint();
		
		//-- public members
		uint64_t endpointID;
					
		//-- public methods
		void sendPacketIn(SVCPacket* packet);
		void sendPacketOut(SVCPacket* packet);
		bool checkInitLiveTime(int interval);
		bool isAuthenticated();
		
		void encryptPacket(SVCPacket* packet);
		void decryptpacket(SVCPacket* packet);
		void connectToAddress(uint32_t remoteAddress);
};

DaemonEndpoint::DaemonEndpoint(uint64_t endpointID){
	
	this->endpointID = endpointID;	
	this->isAuth = false;
	this->initLiveTime = SVC_ENDPOINT_LIVETIME;
	
	this->sha256 = new SHA256();
	
	//-- create dmn unix socket, bind 
	this->dmnSocket = socket(AF_LOCAL, SOCK_DGRAM, 0);
	struct sockaddr_un dmnSockAddr;
	this->dmnSockPath = SVC_ENDPOINT_DMN_PATH_PREFIX + to_string(endpointID);
	memset(&dmnSockAddr, 0, sizeof(dmnSockAddr));
	dmnSockAddr.sun_family = AF_LOCAL;
	memcpy(dmnSockAddr.sun_path, this->dmnSockPath.c_str(), dmnSockPath.size());
	bind(this->dmnSocket, (struct sockaddr*) &dmnSockAddr, sizeof(dmnSockAddr));
	//-- then connect to app socket
	struct sockaddr_un appSockAddr;
	string appSockPath = SVC_ENDPOINT_APP_PATH_PREFIX + to_string(endpointID);
	memset(&appSockAddr, 0, sizeof(appSockAddr));
	appSockAddr.sun_family = AF_LOCAL;
	memcpy(appSockAddr.sun_path, appSockPath.c_str(), appSockPath.size());
	connect(this->dmnSocket, (struct sockaddr*) &appSockAddr, sizeof(appSockAddr));
	
	//-- create a packet handler
	this->packetHandler = new PacketHandler(this->dmnSocket);
	this->packetHandler->setCommandHandler(dmn_endpoint_inner_command_handler, this);

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

void DaemonEndpoint::sendPacketIn(SVCPacket* packet){
	this->packetHandler->sendPacket(packet);
}

void DaemonEndpoint::sendPacketOut(SVCPacket* packet){
	sendto(daemonInSocket, packet->packet,packet->dataLen, 0, (struct sockaddr*)&this->remoteAddr, this->remoteAddrLen);
	//printf("\nsend packet out: "); printBuffer(packet->packet, packet->dataLen); fflush(stdout);
}

bool DaemonEndpoint::checkInitLiveTime(int interval){
	this->initLiveTime -= interval;
	return (this->initLiveTime>0);
}

bool DaemonEndpoint::isAuthenticated(){
	return this->isAuth;
}

//-- endpoint packet handling functions

void DaemonEndpoint::dmn_endpoint_inner_command_handler(SVCPacket* packet, void* args){
	DaemonEndpoint* _this = (DaemonEndpoint*)args;
	enum SVCCommand cmd = (enum SVCCommand)packet->packet[SVC_PACKET_HEADER_LEN];
	
	uint8_t* param = param = (uint8_t*)malloc(SVC_DEFAULT_BUFSIZ);
	uint16_t paramLen;
	string hashx;
	uint8_t* aeskey;
	int requested_security_strength;
	mpz_t randomx;
	char* gx_x;
	uint16_t gx_x_hexlen;
	char* gx_y;
	uint16_t gx_y_hexlen;
	
	uint8_t* encrypted;
	uint32_t encryptedLen;
	
	switch (cmd){
		case SVC_CMD_CONNECT_INNER1:
			//printf("\nCONNECT_INNER1 received");			
			//-- extract remote address
			packet->popCommandParam(param, &paramLen);		
			_this->connectToAddress(*((uint32_t*)param));			
			//-- extract challengeSecret x
			packet->popCommandParam(param, &paramLen);
			//-- use SHA256(x) as an AES256 key
			hashx = _this->sha256->hash(hexToString(param, paramLen));
			stringToHex(hashx, &aeskey); //AES key is guaranteed to be 256 bits length
			_this->aes256 = new AES256(aeskey);
			//-- generate STS-gx
			_this->curve = new ECCurve();
			requested_security_strength = _this->curve->getRequestSecurityLength();
			mpz_init(randomx);
			generateRandomNumber(&randomx, requested_security_strength);
			_this->gx = _this->curve->mul(_this->curve->g, &randomx);
			//-- use created AES to encrypt gx = Ex(gx), copy to param
			gx_x = mpz_get_str(NULL, 16, _this->gx->x);
			gx_x_hexlen = strlen(gx_x);
			paramLen = 0;
			memcpy(param + paramLen, &gx_x_hexlen, 2);
			paramLen += 2;
			memcpy(param + paramLen, gx_x, gx_x_hexlen);
			paramLen += gx_x_hexlen;
			gx_y = mpz_get_str(NULL, 16, _this->gx->y);
			gx_y_hexlen = strlen(gx_y);
			memcpy(param + paramLen, &gx_y_hexlen, 2);
			paramLen += 2;
			memcpy(param+paramLen, gx_y, gx_y_hexlen);
			paramLen += gx_y_hexlen;
			_this->aes256->encrypt(param, paramLen, &encrypted, &encryptedLen);		
			//-- attach Ex(k1) to packet
			packet->pushCommandParam(encrypted, encryptedLen);
			delete encrypted;
			//-- switch commandID
			packet->switchCommand(SVC_CMD_CONNECT_OUTER1);
			//-- sent the packet
			_this->sendPacketOut(packet);
			break;
		default:
			break;
	}
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
		//endpointChecker->stopWorking();
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
			//--else: ignore this packet
			break;
		default:
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
	
	struct sockaddr_un appSockAddr;
	memset(&appSockAddr, 0, sizeof(appSockAddr));
	appSockAddr.sun_family = AF_LOCAL;
	
	switch (cmd){
		case SVC_CMD_CONNECT_OUTER1:
			newEndpointID |= daemonEndpointCounter;
			newEndpointID <<= 48;
			newEndpointID |= endpointID;
			//-- create new daemonEndpoint for this endpointID
			dmnEndpoint = new DaemonEndpoint(newEndpointID);
			endpoints[newEndpointID] = dmnEndpoint;
			//-- extract DH-1
			packet->popCommandParam(param, &paramLen);
			//-- extract appID
			packet->popCommandParam(param, &paramLen);
			//-- send the packet to the corresponding app
			packet->switchCommand(SVC_CMD_CONNECT_INNER2);
			appID = *((uint32_t*)param);
			appSockPath = SVC_CLIENT_PATH_PREFIX + to_string(appID);
			memcpy(&appSockAddr, appSockPath.c_str(), appSockPath.size());
			sendto(daemonUnSocket, packet->packet, packet->dataLen, 0, (struct sockaddr*)&appSockAddr, sizeof(appSockAddr));
			delete packet;
			break;
		default:
			delete packet;
			break;
	}
	
	delete param;
}

void checkEndpointLiveTime(void* args){
	for (auto& it : endpoints){
		if (it.second != NULL){
			DaemonEndpoint* ep = (DaemonEndpoint*)it.second;
			if (!(ep->isAuthenticated() || ep->checkInitLiveTime(1000))){
				//remove this endpoint
				it.second = NULL;
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


