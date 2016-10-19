#include "svc-utils.h"
#include <cstdlib>
#include <netinet/in.h>
#include <unordered_map>
#include <unistd.h>
#include <sys/un.h>
#include <sys/stat.h>

#define SVC_VERSION 0x01

using namespace std;

//--	class forward declaration
class DaemonEndpoint;
//--	method forward declaration
extern void dmn_endpoint_inner_command_handler(SVCPacket* packet, void* args);

//--	GLOBAL VARIABLES
unordered_map<uint64_t, DaemonEndpoint*> endpoints;
struct sockaddr_un daemonSockUnAddress;
struct sockaddr_in daemonSockInAddress;
int daemonUnSocket;
int daemonInSocket;
PacketHandler* unPacketHandler;
PacketHandler* inPacketHandler;
PeriodicWorker* endpointChecker;


class DaemonEndpoint{
	private:
		//-- private members
		bool isAuth;
		int initLiveTime;
		int dmnSocket;
		string dmnSockPath;
		struct sockaddr_in remoteAddr;
		size_t remoteAddrLen;
		PacketHandler* packetHandler;
		
	public:
		//-- constructors/destructors
		DaemonEndpoint(uint64_t endpointID);
		~DaemonEndpoint();
		
		//-- public members
		uint64_t endpointID;
					
		//-- public methods
		void sendPacketToApp(SVCPacket* packet);
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

void DaemonEndpoint::sendPacketToApp(SVCPacket* packet){
	this->packetHandler->sendPacket(packet);
}

void DaemonEndpoint::sendPacketOut(SVCPacket* packet){
	sendto(daemonInSocket, packet->packet,packet->dataLen, 0, (struct sockaddr*)&this->remoteAddr, this->remoteAddrLen);
}

bool DaemonEndpoint::checkInitLiveTime(int interval){
	this->initLiveTime -= interval;
	return (this->initLiveTime>0);
}

bool DaemonEndpoint::isAuthenticated(){
	return this->isAuth;
}

//-- endpoint packet handling functions

void dmn_endpoint_inner_command_handler(SVCPacket* packet, void* args){
	DaemonEndpoint* dmnEndpoint = (DaemonEndpoint*)args;
	enum SVCCommand cmd = (enum SVCCommand)packet->packet[SVC_PACKET_HEADER_LEN];
	
	uint8_t* param = param = (uint8_t*)malloc(SVC_DEFAULT_BUFSIZ);
	uint16_t paramLen;
	switch (cmd){
		case SVC_CMD_CONNECT_INNER1:
			printf("\nCONNECT_INNER1 received");			
			//-- extract remote address
			packet->popCommandParam(param, &paramLen);
			dmnEndpoint->connectToAddress(*((uint32_t*)param));
			//-- extract challengeSecret
			packet->popCommandParam(param, &paramLen);
			//-- use challengeSecret (x) as an AES key
			//-- generate k1
			//-- use created AES to encrypt k1
			//-- attach Ex(k1) to packet
			//-- switch commandID
			packet->switchCommandID(SVC_CMD_CONNECT_OUTER1);
			//-- sent the packet
			dmnEndpoint->sendPacketOut(packet);
			break;
		default:
			break;
	}
}
//============================ SVC DAEMON IMPLEMENTATION ==============================
//-----------------------------------//
/*
void* unixReadingLoop(void* args){
	
	int byteRead;
	vector<Message*> params;

	while (working){	
		do{
			byteRead = recv(daemonUnSocket, unixReceiveBuffer, SVC_DEFAULT_BUFSIZ, MSG_DONTWAIT);
		}
		while((byteRead==-1 && (errno==EAGAIN || errno==EWOULDBLOCK)) && working);		
		
		//--	process message. message is stored in unixReceiveBuffer
		if (byteRead>0){			
			
			printf("\nread from unix: ");
			printBuffer(unixReceiveBuffer, byteRead);
			
			//--	check if we have service for this endPointID
			uint64_t endPointID = *((uint64_t*)unixReceiveBuffer);			
			uint8_t infoByte = unixReceiveBuffer[ENDPOINTID_LENGTH];
			
			DaemonService* service;
			service = getServiceByEndPointID(endPointID);
			
			if (service==NULL){
				if (infoByte & SVC_COMMAND_FRAME){
					enum SVCCommand cmd = (enum SVCCommand)unixReceiveBuffer[ENDPOINTID_LENGTH + 1];
					if (cmd == SVC_CMD_CONNECT_STEP1){
						extractParams(unixReceiveBuffer + ENDPOINTID_LENGTH + 2, &params);
						//--	check for service if connect to the same address
						DaemonService* service;
						uint32_t address = *((uint32_t*)(params[2]->data));
						if (address!=0){
							service = getServiceByAddress(address);							
							if (service == NULL){
								printf("\nno service found for address: %08x, creating new.", address);
								//--TODO:	to be changed to htp
								struct sockaddr_in sockAddr;
								size_t sockLen = sizeof(sockAddr);							
								sockAddr.sin_family = AF_INET;
								sockAddr.sin_port = htons(SVC_DAEPORT);
								sockAddr.sin_addr.s_addr = address;
								printBuffer((uint8_t*)&sockAddr, sockLen);
								service = new DaemonService(&sockAddr, sockLen);
								service->address = address;
								
								//--	add the service
								serviceTableMutex->lock();
								serviceTable.push_back(service);
								serviceTableMutex->unlock();								
							}
							//--	else: use this service
							DaemonEndPoint* endPoint = service->addDaemonEndPoint(endPointID, *((uint32_t*)(params[1]->data)));
							endPoint->outgoingQueue->enqueue(new Message(unixReceiveBuffer, byteRead));						
							clearParams(&params);
						}
						//--	else: incorrect address
					}
					//--	else: other commands not allows without service
				}
				//--	else: data frame not allowed without service
			}		
			else{
				if (service->isWorking()){					
					service->endPointsMutex->lock_shared();
					service->endPoints[endPointID]->outgoingQueue->enqueue(new Message(unixReceiveBuffer, byteRead));
					service->endPointsMutex->unlock_shared();
				}
				//--	else: current service is not working
			}
		}
		//--	else: read error		
	}
	printf("\nExit unix reading loop");
}

void* htpReadingLoop(void* args){
	
	int byteRead;
	struct sockaddr_in sockAddr;
	socklen_t sockLen = sizeof(sockAddr);
	vector<Message*> params;

	while (working){	
		do{
			byteRead = recvfrom(daemonInSocket, htpReceiveBuffer, SVC_DEFAULT_BUFSIZ, MSG_DONTWAIT, (struct sockaddr*) &sockAddr, &sockLen);
		}
		while((byteRead==-1 && (errno==EAGAIN || errno==EWOULDBLOCK)) && working);		
		
		//--	process message. message is stored in unixReceiveBuffer
		if (byteRead>0){			
			
			printf("\nread from htp: ");
			printBuffer(htpReceiveBuffer, byteRead);
			
			//--	check if we have service for this endPointID
			uint32_t sessionID = *((uint32_t*)htpReceiveBuffer);
			uint64_t endPointID = *((uint64_t*)(htpReceiveBuffer+SESSIONID_LENGTH));		
			uint8_t infoByte = htpReceiveBuffer[SESSIONID_LENGTH + ENDPOINTID_LENGTH];
			
			DaemonService* service;
			service = getServiceByEndPointID(endPointID);
			
			if (service==NULL){
				if (infoByte & SVC_COMMAND_FRAME){				
					enum SVCCommand cmd = (enum SVCCommand)htpReceiveBuffer[SESSIONID_LENGTH + ENDPOINTID_LENGTH + 1];
					if (cmd == SVC_CMD_CONNECT_STEP1){
						if ((infoByte & 0x30)>>4 == SVC_VERSION){
							extractParams(htpReceiveBuffer + SESSIONID_LENGTH + ENDPOINTID_LENGTH + 2, &params);
							//--	check if we have service for this sessionID
							if (sessionID!=SVC_DEFAULT_SESSIONID){
								service = getServiceBySessionID(sessionID);
							}
							//--else: create new service
							if (service==NULL){						
								//--	create new DaemonService
								service = new DaemonService(&sockAddr, sockLen);
								//--	register this service with endPointID
								serviceTableMutex->lock();
								serviceTable[endPointID] = service;
								serviceTableMutex->unlock();
							}
							//--else: use this service
							DaemonEndPoint* endPoint = service->addDaemonEndPoint(endPointID, *((uint32_t*)(params[1]->data)));
							endPoint->incomingQueue->enqueue(new Message(htpReceiveBuffer + SESSIONID_LENGTH, byteRead-SESSIONID_LENGTH));
							clearParams(&params);
						}
						else{
							printf("\nversion mismatch, CONNECT_STEP1 reject");
						}
						//--else: version mismatched
					}
					//--else: other commands not allowed without service
				}
				//--else: data frame not allowed without service
			}
			else{
				//--	service existed with endPointID, remove sessionID before forward
				if (service->isWorking()){
					service->endPointsMutex->lock_shared();
					service->endPoints[endPointID]->incomingQueue->enqueue(new Message(htpReceiveBuffer + SESSIONID_LENGTH, byteRead-SESSIONID_LENGTH));
					service->endPointsMutex->unlock_shared();	
				}
				//--	else: current service is not working
			}
		}
		//--	else: read error
	}
	printf("\nExit htp reading loop");
}
*/

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
				endpoint->sendPacketToApp(packet);
			}
			//--else: ignore this packet
			break;
		default:
			break;
	}
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
	inPacketHandler->setCommandHandler(NULL, NULL);
	
	//--	create a thread to check for daemon endpoints' lives
	endpointChecker = new PeriodicWorker(1000, checkEndpointLiveTime, NULL);
	
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


