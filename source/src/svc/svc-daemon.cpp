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

PacketHandler* daemonUnixIncomingPacketHandler;
PacketHandler* daemonUnixOutgoingPacketHandler;
PacketHandler* daemonInetIncomingPacketHandler;
//PacketHandler* daemonInetOutgoingPacketHandler;
PeriodicWorker* endpointChecker;
uint16_t daemonEndpointCounter = 0;
volatile bool working;

//-- queues
MutexedQueue<SVCPacket*>* daemonUnixIncomingQueue;
MutexedQueue<SVCPacket*>* daemonUnixOutgoingQueue;
MutexedQueue<SVCPacket*>* daemonInetIncomingQueue;
//MutexedQueue<SVCPacket*>* inetOutgoingQueue;

//-- reading loops and threads
pthread_t daemonUnixReadingThread;
pthread_t daemonUnixWritingThread;
pthread_t daemonInetReadingThread;
extern void* daemon_unix_reading_loop(void* args);
extern void* daemon_unix_writing_loop(void* args);
extern void* daemon_inet_reading_loop(void* args);

class DaemonEndpoint{
	public:
		//-- static methods
		static void daemon_endpoint_unix_incoming_packet_handler(SVCPacket* packet, void* args);
		static void daemon_endpoint_unix_outgoing_packet_handler(SVCPacket* packet, void* args);		
		static void daemon_endpoint_inet_incoming_packet_handler(SVCPacket* packet, void* args);
		static void daemon_endpoint_inet_outgoing_packet_handler(SVCPacket* packet, void* args);
		
		static void* daemon_endpoint_unix_reading_loop(void* args);
		static void* daemon_endpoint_unix_writing_loop(void* args);
		//static void* daemon_endpoint_inet_reading_loop(void* args);
		static void* daemon_endpoint_inet_writing_loop(void* args);
		
		MutexedQueue<SVCPacket*>* unixIncomingQueue;
		MutexedQueue<SVCPacket*>* unixOutgoingQueue;
		MutexedQueue<SVCPacket*>* unixToBeSentQueue;
		MutexedQueue<SVCPacket*>* inetIncomingQueue;
		MutexedQueue<SVCPacket*>* inetOutgoingQueue;
		MutexedQueue<SVCPacket*>* inetToBeSentQueue;
		
		PacketHandler* unixIncomingPacketHandler;
		PacketHandler* unixOutgoingPacketHandler;
		//PacketHandler* inetIncomingPacketHandler;
		PacketHandler* inetOutgoingPacketHandler;
		
		pthread_t unixReadingThread;
		pthread_t unixWritingThread;
		pthread_t inetWritingThread;
		
		//-- private members
		volatile bool working;
		bool isAuth;
		int initLiveTime;
		int dmnSocket;
		string dmnSockPath;
		struct sockaddr_in remoteAddr;
		size_t remoteAddrLen;

		//-- crypto protocol variables	
		SVCPacket* encryptedECPoint;
		SVCPacket* encryptedProof;
		ECCurve* curve;
		mpz_t randomX;		
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
		bool checkInitLiveTime(int interval);
		bool isAuthenticated();
		
		int connectToAppSocket();
		int startInetHandlingRoutine();
		void encryptPacket(SVCPacket* packet);
		void decryptPacket(SVCPacket* packet);
		int connectToAddress(uint32_t remoteAddress);
		int connectToAddress(const struct sockaddr_in* sockAddr, socklen_t sockLen);
		
		void shutdown();
};

DaemonEndpoint::DaemonEndpoint(uint64_t endpointID){
	
	const char* error;
	
	this->unixReadingThread = 0;
	this->unixWritingThread = 0;
	
	this->working = true;
	this->endpointID = endpointID;	
	this->isAuth = false;
	this->initLiveTime = SVC_ENDPOINT_LIVETIME;
	
	this->sendSequence = 0;
	this->recvSequence = 0;
	this->unixIncomingPacketHandler = NULL;
	this->unixOutgoingPacketHandler = NULL;
	
	this->sendSequenceMutex = new SharedMutex();
	this->recvSequenceMutex = new SharedMutex();
	
	//-- init queues
	this->unixIncomingQueue = new MutexedQueue<SVCPacket*>();
	this->unixOutgoingQueue = new MutexedQueue<SVCPacket*>();
	this->unixToBeSentQueue = new MutexedQueue<SVCPacket*>();
	this->inetIncomingQueue = new MutexedQueue<SVCPacket*>();
	this->inetOutgoingQueue = new MutexedQueue<SVCPacket*>();
	this->inetToBeSentQueue = new MutexedQueue<SVCPacket*>();
	
	this->aesgcm = NULL;
	this->sha256 = new SHA256();
	
	//-- create dmn unix socket, bind 
	this->dmnSocket = socket(AF_LOCAL, SOCK_DGRAM, 0);
	struct sockaddr_un dmnSockAddr;
	this->dmnSockPath = string(SVC_ENDPOINT_DMN_PATH_PREFIX) + hexToString((uint8_t*)&endpointID, ENDPOINTID_LENGTH);
	memset(&dmnSockAddr, 0, sizeof(dmnSockAddr));
	dmnSockAddr.sun_family = AF_LOCAL;
	memcpy(dmnSockAddr.sun_path, this->dmnSockPath.c_str(), dmnSockPath.size());
	
	if (bind(this->dmnSocket, (struct sockaddr*) &dmnSockAddr, sizeof(dmnSockAddr)) == -1){
		error = SVC_ERROR_BINDING;
		goto endpoint_error;
	}
	else{		
		//-- create a reading thread
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		if (pthread_create(&this->unixReadingThread, &attr, daemon_endpoint_unix_reading_loop, this) !=0){
			error = SVC_ERROR_CRITICAL;
			goto endpoint_error;
		}
		//-- create a packet handler
		this->unixIncomingPacketHandler = new PacketHandler(this->unixIncomingQueue, daemon_endpoint_unix_incoming_packet_handler, this);
		this->unixOutgoingPacketHandler = new PacketHandler(this->unixOutgoingQueue, daemon_endpoint_unix_outgoing_packet_handler, this);
		goto endpoint_success;
	}
	
	endpoint_error:
		delete this->sha256;
		delete sendSequenceMutex;
		delete recvSequenceMutex;
		delete this->unixIncomingQueue;
		delete this->unixOutgoingQueue;
		delete this->unixToBeSentQueue;
		delete this->inetIncomingQueue;
		delete this->inetOutgoingQueue;
		delete this->inetToBeSentQueue;
		throw error;
		
	endpoint_success:
		printf("\nendpoint created"); fflush(stdout);
}

void DaemonEndpoint::daemon_endpoint_unix_outgoing_packet_handler(SVCPacket* packet, void* args){
	DaemonEndpoint* _this = (DaemonEndpoint*)args;
	if (_this->working){	
		_this->unixToBeSentQueue->enqueue(packet);
	}
	else{
		delete packet;
	}
}

void DaemonEndpoint::shutdown(){
	//printf("\nendpoint shutdown called with this = NULL?: %d ", this == NULL); printBuffer((uint8_t*)&this->endpointID, ENDPOINTID_LENGTH);fflush(stdout);
	if (this->working){
		//printf("\ndaemonEndpointShutdown called"); fflush(stdout);
		this->working = false;
		if (this->unixReadingThread!=0) pthread_join(this->unixReadingThread, NULL);
		if (this->unixWritingThread!=0) pthread_join(this->unixWritingThread, NULL);
		
		//-- clean up
		//printf("\nclean up phase 1"); fflush(stdout);
		
		delete sendSequenceMutex;
		delete recvSequenceMutex;				
		delete this->sha256;
		
		//printf("\nclean up phase 2"); fflush(stdout);
		if (this->unixIncomingPacketHandler!=NULL){
			this->unixIncomingPacketHandler->stopWorking();
			this->unixIncomingPacketHandler->waitStop();
		}
		//printf("\nclean up phase 3"); fflush(stdout);
		if (this->unixOutgoingPacketHandler!=NULL){
			this->unixOutgoingPacketHandler->stopWorking();
			this->unixOutgoingPacketHandler->waitStop();
		}
		
		//-- remove queues
		delete this->unixIncomingQueue;
		delete this->unixOutgoingQueue;
		delete this->unixToBeSentQueue;
		delete this->inetIncomingQueue;
		delete this->inetOutgoingQueue;
		delete this->inetToBeSentQueue;
		
		//printf("\ntrying to unlink: %s", this->dmnSockPath.c_str());
		unlink(this->dmnSockPath.c_str());
		printf("\nendpoint shut down"); fflush(stdout);
	}
}

DaemonEndpoint::~DaemonEndpoint(){	
	shutdown();
}

int DaemonEndpoint::connectToAppSocket(){
	//-- then connect to app socket
	//printf("\nconnectToAppSocket inside"); fflush(stdout);
	struct sockaddr_un appSockAddr;
	string appSockPath = string(SVC_ENDPOINT_APP_PATH_PREFIX) + hexToString((uint8_t*)&endpointID, ENDPOINTID_LENGTH);
	memset(&appSockAddr, 0, sizeof(appSockAddr));
	appSockAddr.sun_family = AF_LOCAL;
	memcpy(appSockAddr.sun_path, appSockPath.c_str(), appSockPath.size());
	//printf("\nconnectToAppSocket path copied: %s", appSockPath.c_str()); fflush(stdout);
	if (connect(this->dmnSocket, (struct sockaddr*) &appSockAddr, sizeof(appSockAddr)) == 0){
		//-- start daemon endpoint unix writing
		printf("\ndaemon endpoint connected to app endpoint");
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		return pthread_create(&this->unixWritingThread, &attr, daemon_endpoint_unix_writing_loop, this);
	}
	else{
		printf("\nconnectToAppSocket connect fail"); fflush(stdout);
		return -1;
	}
}

int DaemonEndpoint::startInetHandlingRoutine(){
	//-- create packethandler for inet outgoing packet and writing thread
	this->inetOutgoingPacketHandler = new PacketHandler(this->inetOutgoingQueue, daemon_endpoint_inet_outgoing_packet_handler, this);
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	return pthread_create(&this->inetWritingThread, &attr, daemon_endpoint_inet_writing_loop, this);
}

int DaemonEndpoint::connectToAddress(uint32_t remoteAddress){
	this->remoteAddrLen = sizeof(this->remoteAddr);							
	this->remoteAddr.sin_family = AF_INET;
	this->remoteAddr.sin_port = htons(SVC_DAEPORT);
	this->remoteAddr.sin_addr.s_addr = remoteAddress;
	return startInetHandlingRoutine();	
}

int DaemonEndpoint::connectToAddress(const struct sockaddr_in* sockAddr, socklen_t sockLen){
	memcpy(&this->remoteAddr, sockAddr, sockLen);
	this->remoteAddrLen = sockLen;
	return startInetHandlingRoutine();
}


void DaemonEndpoint::daemon_endpoint_inet_outgoing_packet_handler(SVCPacket* packet, void* args){
	DaemonEndpoint* _this = (DaemonEndpoint*)args;
	//printf("\ndaemon endpoint forward packet to inetToBeSentQueue"); fflush(stdout);
	_this->inetToBeSentQueue->enqueue(packet);
}

void* DaemonEndpoint::daemon_endpoint_inet_writing_loop(void* args){
	DaemonEndpoint* _this = (DaemonEndpoint*)args;
	SVCPacket* packet;
	while (_this->working){
		packet = _this->inetToBeSentQueue->dequeueWait(1000);
		if (packet!=NULL){
			sendto(daemonInSocket, packet->packet, packet->dataLen, 0, (struct sockaddr*)&_this->remoteAddr, _this->remoteAddrLen);
			//printf("\ndaemon endpoint send packet to internet: "); printBuffer(packet->packet, packet->dataLen); fflush(stdout);
			delete packet;
		};
	}
	pthread_exit(EXIT_SUCCESS);
}


bool DaemonEndpoint::checkInitLiveTime(int interval){
	this->initLiveTime -= interval;
	return (this->initLiveTime>0);
}

bool DaemonEndpoint::isAuthenticated(){
	return this->isAuth;
}

//-- endpoint packet handling functions

void* DaemonEndpoint::daemon_endpoint_unix_reading_loop(void* args){
	DaemonEndpoint* _this = (DaemonEndpoint*)args;
	
	int readrs;
	uint8_t* buffer = (uint8_t*)malloc(SVC_DEFAULT_BUFSIZ);	
	while (_this->working){
		do{
				readrs = recv(_this->dmnSocket, buffer, SVC_DEFAULT_BUFSIZ, MSG_DONTWAIT);
		}
		while((readrs==-1) && _this->working);
		
		if (readrs>0){
			//printf("\ndaemon endpoint unix read packet: "); printBuffer(buffer, readrs); fflush(stdout);
			_this->unixIncomingQueue->enqueue(new SVCPacket(buffer, readrs));
		}
	}
	free(buffer);
	pthread_exit(EXIT_SUCCESS);
}

void* DaemonEndpoint::daemon_endpoint_unix_writing_loop(void* args){
	DaemonEndpoint* _this = (DaemonEndpoint*)args;
	SVCPacket* packet;
	int sendrs;
	//printf("\ndaemon_endpoint_unix_writing_loop started"); fflush(stdout);
	while (_this->working){
		packet = _this->unixToBeSentQueue->dequeueWait(1000);
		//printf("\ndaemon_endpoint_unix_writing_loop dequeueWait returned");
		if (packet!=NULL){
			sendrs = send(_this->dmnSocket, packet->packet, packet->dataLen, 0);
			printf("\ndaemon endpoint send packet: "); printBuffer(packet->packet, packet->dataLen); fflush(stdout);
			delete packet;		
		}
	}
	pthread_exit(EXIT_SUCCESS);
}

void DaemonEndpoint::daemon_endpoint_unix_incoming_packet_handler(SVCPacket* packet, void* args){
	
	static uint8_t param[SVC_DEFAULT_BUFSIZ];
	static uint16_t paramLen;
	
	//printf("\ndaemon_endpoint_unix_incoming_packet_handler process a packet");
	
	uint8_t infoByte = packet->packet[INFO_BYTE];	
	if ((infoByte & SVC_COMMAND_FRAME) != 0x00){
		DaemonEndpoint* _this = (DaemonEndpoint*)args;
		enum SVCCommand cmd = (enum SVCCommand)packet->packet[CMD_BYTE];		
		uint64_t endpointID = *((uint64_t*)packet->packet);
	
		string hashValue;
		uint8_t* aeskey;
		AES256* aes256 = NULL;
		int requested_security_strength;
		mpz_t randomNumber;
	
		char* ecpointHexString;
		uint16_t ecpointHexLen;
	
		string solutionProof;
		string solution;
	
		uint8_t* iv;
		uint32_t ivLen;
		uint8_t* encrypted;
		uint32_t encryptedLen;
		uint8_t* tag;
		uint32_t tagLen;
	
		uint8_t* data;
		uint32_t dataLen;
	
		ECPoint* ecpoint;
		int sendrs;
			
		switch (cmd){			
		
			case SVC_CMD_SHUTDOWN_ENDPOINT:
				printf("\nSVC_SHUTDOWN_ENDPOINT received for: "); printBuffer((uint8_t*) &_this->endpointID, ENDPOINTID_LENGTH); fflush(stdout);
				delete packet;
				_this->shutdown();
				break;
			
			case SVC_CMD_CONNECT_INNER1:
				if (!_this->isAuth){
					//printf("\nreceived packet: "); printBuffer(packet->packet, packet->dataLen);
					printf("\nSVC_CMD_CONNECT_INNER1 received"); fflush(stdout);	
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
					//printf("\naeskey used to encrypt gx: "); printBuffer(aeskey, KEY_LENGTH); fflush(stdout);
					free(aeskey);
					//-- generate STS-gx
					if (_this->curve == NULL) _this->curve = new ECCurve();
					requested_security_strength = _this->curve->getRequestSecurityLength();
					mpz_init(_this->randomX);
					generateRandomNumber(&_this->randomX, requested_security_strength);
					ecpoint = _this->curve->mul(_this->curve->g, &_this->randomX);
				
					paramLen = 0;
					//-- use created AES to encrypt gx = Ex(gx), copy to param
					ecpointHexString = mpz_get_str(NULL, 16, ecpoint->x);
					ecpointHexLen = strlen(ecpointHexString) + 1;			
					//printf("\nsent gx_x: %s", ecpointHexString); fflush(stdout);				
					memcpy(param + paramLen, &ecpointHexLen, 2);
					paramLen += 2;
					memcpy(param + paramLen, ecpointHexString, ecpointHexLen);	
					paramLen += ecpointHexLen;
					free(ecpointHexString);
				
					ecpointHexString = mpz_get_str(NULL, 16, ecpoint->y);
					ecpointHexLen = strlen(ecpointHexString)+1; 
					//printf("\nsent gx_y: %s", ecpointHexString); fflush(stdout);
					memcpy(param + paramLen, &ecpointHexLen, 2);
					paramLen += 2;				
					memcpy(param+paramLen, ecpointHexString, ecpointHexLen);
					paramLen += ecpointHexLen;								
					free(ecpointHexString);
				
					aes256->encrypt(param, paramLen, &encrypted, &encryptedLen);
					//printf("\nsent encrypted gx: "); printBuffer(encrypted, encryptedLen);
								
					//-- attach Ex(k1) to packet
					packet->pushCommandParam(encrypted, encryptedLen);
					free(encrypted);
				
					//-- switch commandID
					packet->switchCommand(SVC_CMD_CONNECT_OUTER1);
					//-- send the packet to internet
					_this->inetOutgoingQueue->enqueue(packet);
				}
				else{
					delete packet;
				}				
				break;
			
			case SVC_CMD_CONNECT_INNER3:
				printf("\nSVC_CMD_CONNECT_INNER3 received"); fflush(stdout);
				//-- app responded with CONNECT_INNER3, now can connect to app socket
			
				_this->connectToAppSocket();
				packet->popCommandParam(param, &paramLen);
				//-- use SHA256(x) as an AES256 key
				hashValue = _this->sha256->hash(string((char*)param, paramLen));
				stringToHex(hashValue, &aeskey); //-- aes key used to decrypt k1
				aes256 = new AES256(aeskey);
				//printf("\naeskey used to decrypt gx: "); printBuffer(aeskey, KEY_LENGTH);
				free(aeskey);
				aes256->decrypt(_this->encryptedECPoint->packet, _this->encryptedECPoint->dataLen, &data, &dataLen);
				//-- remove the saved encryptedpoint packet
				delete _this->encryptedECPoint;
				//-- construct gx from decrypted K1
				//printf("\nreceived gxx || gxy: "); printBuffer(data, dataLen); fflush(stdout);
				paramLen = *((uint16_t*)data);
				//printf("\nreceived gx_x: %s", data + 2);
				//printf("\ngx_y by printBuffer: "); printBuffer(data + 4 + paramLen, dataLen - 4 - paramLen); fflush(stdout);
				//printf("\nreceived gx_y: %s", data + 4 + paramLen); fflush(stdout);
			
				//-- !! check if the decrypt ecpoint data is at least VALID, by verifying the null-terminator at the end of each number
				//-- otherwise the new ECPoint will be created with buffer-overflow error
				if ((data[1+paramLen] == 0x00) && (data[dataLen-1] == 0x00)){
					ecpoint = new ECPoint((char*)(data + 2) , (char*)(data + 4 + paramLen));				
					free(data);
					//-- extract challengeSecret y
					packet->popCommandParam(param, &paramLen);
					//-- use SHA256(y) as an AES256 key
					hashValue = _this->sha256->hash(string((char*)param, paramLen));
					//-- create new aes key to encrypt
					stringToHex(hashValue, &aeskey);
					delete aes256;
					aes256 = new AES256(aeskey);
					//printf("\naeskey used to encrypt gy: ");printBuffer(aeskey, KEY_LENGTH);
					free(aeskey);
				
					//-- generate random number y
					if (_this->curve == NULL) _this->curve = new ECCurve();
					requested_security_strength = _this->curve->getRequestSecurityLength();
					mpz_init(randomNumber);
					generateRandomNumber(&randomNumber, requested_security_strength);			
					//-- generate shared secret gxy			
					_this->gxy = _this->curve->mul(ecpoint, &randomNumber);
					ecpointHexString = mpz_get_str(NULL, 16, _this->gxy->x);
					ecpointHexLen = strlen(ecpointHexString);
					memcpy(param, ecpointHexString, ecpointHexLen);
					paramLen = ecpointHexLen;
					free(ecpointHexString);
				
					ecpointHexString = mpz_get_str(NULL, 16, _this->gxy->x);
					ecpointHexLen = strlen(ecpointHexString);
					memcpy(param + paramLen , ecpointHexString, ecpointHexLen);
					paramLen += ecpointHexLen;
					free(ecpointHexString);
				
					if (_this->aesgcm == NULL){
						//-- aesgcm key = hash(gxy.x || gxy.y)
						hashValue = _this->sha256->hash(string((char*)param, paramLen));
						stringToHex(hashValue, &aeskey);
						_this->aesgcm = new AESGCM(aeskey, (enum SecurityParameter)requested_security_strength);
						//-- free this memory
						//printf("\naesgcm key: "); printBuffer(aeskey, KEY_LENGTH);
						free(aeskey);
					}
				
					//-- pop solution proof to be encrypted
					packet->popCommandParam(param, &paramLen);
					solutionProof = string((char*)param, paramLen);
				
					//-- gererate STS-gy
					ecpoint = _this->curve->mul(_this->curve->g, &randomNumber);
				
					//-- use created AES to encrypt gy = Ey(gy), copy to param
					ecpointHexString = mpz_get_str(NULL, 16, ecpoint->x);
					ecpointHexLen = strlen(ecpointHexString) + 1;
					//printf("\nsent gy_x: %s", ecpointHexString);
					paramLen = 0;
					memcpy(param + paramLen, &ecpointHexLen, 2);
					paramLen += 2;
					memcpy(param + paramLen, ecpointHexString, ecpointHexLen);
					paramLen += ecpointHexLen;
				
					ecpointHexString = mpz_get_str(NULL, 16, ecpoint->y);
					ecpointHexLen = strlen(ecpointHexString) + 1;
					//printf("\nsent gy_y: %s", ecpointHexString);
					memcpy(param + paramLen, &ecpointHexLen, 2);
					paramLen += 2;
					memcpy(param+paramLen, ecpointHexString, ecpointHexLen);
					paramLen += ecpointHexLen;
					aes256->encrypt(param, paramLen, &encrypted, &encryptedLen);
					
					//-- switch command
					packet->switchCommand(SVC_CMD_CONNECT_OUTER2);
					//-- attach Ey(gy) to packet
					packet->pushCommandParam(encrypted, encryptedLen);
					//printf("\nsent Ey(gy): "); printBuffer(encrypted, encryptedLen);
					free(encrypted);
				
					//-- encrypt solution proof then attach to packet
					//-- generate random iv, the first 2 byte are used to store ivLen				
					generateRandomData(requested_security_strength, param + 2);
				
					_this->aesgcm->encrypt(param + 2, requested_security_strength, (uint8_t*)solutionProof.c_str(), solutionProof.size(), NULL, 0, &encrypted, &encryptedLen, &tag, &tagLen);
				
					//printf("\niv: "); printBuffer(param+2, requested_security_strength);
					//-- add iv, encrypted and tag to param				
					paramLen = 0;
					memcpy(param + paramLen, &requested_security_strength, 2);
					paramLen += 2 + requested_security_strength;
					//-- iv is already pre-generated
					memcpy(param + paramLen, &encryptedLen, 2);
					paramLen += 2;
					memcpy(param + paramLen, encrypted, encryptedLen);
					paramLen += encryptedLen;
					//printf("\nencrypted proof: "); printBuffer(encrypted, encryptedLen);
					memcpy(param + paramLen, &tagLen, 2);
					paramLen += 2;
					memcpy(param + paramLen, tag, tagLen);
					paramLen += tagLen;
					//printf("\ntag: "); printBuffer(tag, tagLen);
					packet->pushCommandParam(param, paramLen);
					//printf("\nsent encrypted proof (printBuffer): "); printBuffer(param, paramLen);
					free(encrypted);
					free(tag);
				
					//-- send this packet to internet
					_this->inetOutgoingQueue->enqueue(packet);
				}
				else{
					//-- decryted gx is damaged, delete data
					free(data);
					delete packet;
				}
				break;		
			
			case SVC_CMD_CONNECT_INNER5:
				printf("\nSVC_CMD_CONNECT_INNER5 received");					
				packet->popCommandParam(param, &paramLen);
				//solution = string((char*)param, paramLen);
				//printf("\ndmn Endpoint received solution: %s", solution.c_str()); fflush(stdout);
			
				//-- hash this solution to create the aes256 key to decrypt encryptedECPoint from CONNECT_OUTER2
				hashValue = _this->sha256->hash(string((char*)param, paramLen));
				stringToHex(hashValue, &aeskey); //-- aes key used to decrypt k1
				aes256 = new AES256(aeskey);
				//printf("\naeskey used to decrypt gy: "); printBuffer(aeskey, KEY_LENGTH);
				free(aeskey);
				aes256->decrypt(_this->encryptedECPoint->packet, _this->encryptedECPoint->dataLen, &data, &dataLen);
				//-- remove the saved encrypedEcpoint
				delete _this->encryptedECPoint;
				//-- construct gy from decrypted k2
			
				paramLen = *((uint16_t*)data);
				printf("\nreceived gy_x: %s", data + 2);
				//printf("\ngx_y by printBuffer: "); printBuffer(data + 4 + paramLen, dataLen - 4 - paramLen); fflush(stdout);
				printf("\nreceived gy_y: %s", data + 4 + paramLen); fflush(stdout);
				//-- !! check these gy_x and gy_y
				if ((data[1+paramLen] == 0x00) && (data[dataLen-1] == 0x00)){
					ecpoint = new ECPoint((char*)(data + 2) , (char*)(data + 4 + paramLen));
					free(data);
					//-- generate shared secret gxy
					_this->gxy = _this->curve->mul(ecpoint, &_this->randomX);
				
					//-- generate aesgcm to decrypt solution proof
					ecpointHexString = mpz_get_str(NULL, 16, _this->gxy->x);
					ecpointHexLen = strlen(ecpointHexString);
					memcpy(param, ecpointHexString, ecpointHexLen);
					paramLen = ecpointHexLen;
					free(ecpointHexString);
				
					ecpointHexString = mpz_get_str(NULL, 16, _this->gxy->x);
					ecpointHexLen = strlen(ecpointHexString);
					memcpy(param + paramLen , ecpointHexString, ecpointHexLen);
					paramLen += ecpointHexLen;
					free(ecpointHexString);
				
					if (_this->aesgcm == NULL){
						//-- aesgcm key = hash(gxy.x || gxy.y)
						hashValue = _this->sha256->hash(string((char*)param, paramLen));
						stringToHex(hashValue, &aeskey);
						//printf("\naesgcm key: "); printBuffer(aeskey, KEY_LENGTH);
						_this->aesgcm = new AESGCM(aeskey, (enum SecurityParameter)requested_security_strength);
						//-- free this memory
						free(aeskey);
					
						//-- decrypt the solution proof
						iv = _this->encryptedProof->packet+2;
						ivLen = *((uint16_t*)_this->encryptedProof->packet);
						//printf("\niv : "); printBuffer((uint8_t*)iv, ivLen);
						encrypted = _this->encryptedProof->packet + 4 + ivLen;
						encryptedLen = *((uint16_t*)(_this->encryptedProof->packet + 2 + ivLen));		
						//printf("\nencrypt proof: "); printBuffer(encrypted, encryptedLen);
						tag = _this->encryptedProof->packet + 6 + ivLen + encryptedLen;
						tagLen = *((uint16_t*)(_this->encryptedProof->packet + 4 + ivLen + encryptedLen));
						//printf("\ntag : "); printBuffer(tag, tagLen);
						if (_this->aesgcm->decrypt(iv, ivLen, encrypted, encryptedLen, NULL, 0, tag, tagLen, &data, &dataLen)){
							//-- sultion proof decrypted succeeded by aesgcm
							//printf("\nsolution proof decrypted: %s", string((char*)data, dataLen).c_str()); fflush(stdout);
							//-- forward CONNECT_INNER6 to app
							packet->switchCommand(SVC_CMD_CONNECT_INNER6);
							packet->pushCommandParam(data, dataLen);
							//printf("\nsend this INNER6 to app: "); printBuffer(packet->packet, packet->dataLen); fflush(stdout);
							//printf("\nsend inner6 result: %d ", 
							_this->unixOutgoingQueue->enqueue(packet);
							free(data);
						}
						else{
							printf("\naesgcm decrypt failed");
							delete packet;
						}				
					}
					else{
						delete packet;
					}
					//--	else: _this->aesgcm is not null			
				}
				else{				
					//printf("\ndecrypted gy damaged, delete data");
					free(data);
					delete packet;
				}
				break;
			
			case SVC_CMD_CONNECT_INNER7:
				printf("\nSVC_CMD_CONNECT_INNER7 received"); fflush(stdout);
				//-- authenticated
				_this->isAuth = true;			
				//-- encrypt solution proof then attach to packet
				packet->popCommandParam(param, &paramLen);
				solutionProof = string((char*)param, paramLen);
				//-- generate random iv, the first 2 byte are used to store ivLen				
				generateRandomData(requested_security_strength, param + 2);
			
				_this->aesgcm->encrypt(param + 2, requested_security_strength, (uint8_t*)solutionProof.c_str(), solutionProof.size(), NULL, 0, &encrypted, &encryptedLen, &tag, &tagLen);
			
				//printf("\niv: "); printBuffer(param+2, requested_security_strength);
				//-- add iv, encrypted and tag to param				
				paramLen = 0;
				memcpy(param + paramLen, &requested_security_strength, 2);
				paramLen += 2 + requested_security_strength;
				//-- iv is already pre-generated
				memcpy(param + paramLen, &encryptedLen, 2);
				paramLen += 2;
				memcpy(param + paramLen, encrypted, encryptedLen);
				paramLen += encryptedLen;
				//printf("\nencrypted proof: "); printBuffer(encrypted, encryptedLen);
				memcpy(param + paramLen, &tagLen, 2);
				paramLen += 2;
				memcpy(param + paramLen, tag, tagLen);
				paramLen += tagLen;
				//printf("\ntag: "); printBuffer(tag, tagLen);
				packet->switchCommand(SVC_CMD_CONNECT_OUTER3);
				packet->pushCommandParam(param, paramLen);			
				_this->inetOutgoingQueue->enqueue(packet);
				free(encrypted);
				free(tag);
				break;
			
			case SVC_CMD_CONNECT_OUTER3:
				printf("\nSVC_CMD_CONNECT_OUTER3 received"); fflush(stdout);
				//-- decrypt solution proof
				packet->popCommandParam(param, &paramLen);
				iv = param+2;
				ivLen = *((uint16_t*)param);
				//printf("\niv : "); printBuffer((uint8_t*)iv, ivLen);
				encrypted = param + 4 + ivLen;
				encryptedLen = *((uint16_t*)(param + 2 + ivLen));		
				//printf("\nencrypt proof: "); printBuffer(encrypted, encryptedLen);
				tag = param + 6 + ivLen + encryptedLen;
				tagLen = *((uint16_t*)(param + 4 + ivLen + encryptedLen));
				//printf("\ntag : "); printBuffer(tag, tagLen);		

				if (_this->aesgcm->decrypt(iv, ivLen, encrypted, encryptedLen, NULL, 0, tag, tagLen, &data, &dataLen)){
					//printf("\ndecrypted success"); fflush(stdout);
					//-- solution proof decrypted succeeded by aesgcm
					//printf("\nsolution proof decrypted: %s", string((char*)data, dataLen).c_str()); fflush(stdout);
					//-- forward CONNECT_INNER8 to app
					packet->switchCommand(SVC_CMD_CONNECT_INNER8);
					packet->pushCommandParam(data, dataLen);
					_this->unixOutgoingQueue->enqueue(packet);
					//printf("\nsend this CONNECT_INNER8 to app %d %d: ", sendrs, errno); printBuffer(packet->packet, packet->dataLen); fflush(stdout);
					free(data);
				}
				else{
					delete packet;
					printf("\naesgcm decrypt failed");
				}
				break;
			
			case SVC_CMD_CONNECT_INNER9:
				//-- connection established
				printf("\nSVC_CMD_CONNECT_INNER9 received"); fflush(stdout);
				_this->isAuth = true;
				delete packet;
				break;
				
			
			case SVC_CMD_CONNECT_OUTER2:				
				//-- pop encrypted proof
				packet->popCommandParam(param, &paramLen);
				_this->encryptedProof = new SVCPacket(param, paramLen);			
				packet->popCommandParam(param, &paramLen);
				_this->encryptedECPoint = new SVCPacket(param, paramLen);
		
				//-- change command to INNER_4
				printf("\nchange command to SVC_CMD_CONNECT_INNER4: %d", SVC_CMD_CONNECT_INNER4); fflush(stdout);
				packet->switchCommand(SVC_CMD_CONNECT_INNER4);
				//-- app svc is still waiting for the 'old' endpointID, push the current endpointID as new param
				packet->pushCommandParam(packet->packet, ENDPOINTID_LENGTH);
				//-- clear the 6&7 byte of endpointID
				packet->packet[6]=0x00;
				packet->packet[7]=0x00;
				printf("\nSVC_CMD_CONNECT_INNER4 to be enqueued: ");
				printBuffer(packet->packet, packet->dataLen); fflush(stdout);
				_this->unixOutgoingQueue->enqueue(packet);	
				break;			
			
			default:
				delete packet;
				break;
		}
		_this->unixIncomingPacketHandler->notifyCommand(cmd, endpointID);
	}
	else{
		//-- incoming data, need decryption before forwarding
	}
}


//================================	DAEMON CODE ==============================

void* daemon_unix_reading_loop(void* args){	
	//-- read from unix socket then enqueue to incoming queue
	uint8_t* const buffer = (uint8_t*)malloc(SVC_DEFAULT_BUFSIZ);
	ssize_t readrs;
		
	while (working){
		do{
			readrs = recv(daemonUnSocket, buffer, SVC_DEFAULT_BUFSIZ, MSG_DONTWAIT);
		}
		while((readrs==-1) && working);
		
		if (readrs>0){
			//printf("\ndaemon_unix_reading_loop read a packet: "); printBuffer(buffer, readrs);
			daemonUnixIncomingQueue->enqueue(new SVCPacket(buffer, readrs));
		}
		//else: read received nothing
	}	
	free(buffer);
	pthread_exit(EXIT_SUCCESS);
}

void* daemon_inet_reading_loop(void* args){
	struct sockaddr_in srcAddr;
	socklen_t srcAddrLen;
	int readrs;
	SVCPacket* packet;
	
	uint8_t* buffer = (uint8_t*)malloc(SVC_DEFAULT_BUFSIZ);
	
	while (working){
		do{
			srcAddrLen = sizeof(srcAddr);
			readrs = recvfrom(daemonInSocket, buffer, SVC_DEFAULT_BUFSIZ, MSG_DONTWAIT, (struct sockaddr*)&srcAddr, &srcAddrLen);			
		}
		while((readrs==-1) && working);
		
		if (readrs>0){
			//printf("\ndaemon_inet_reading_loop read a packet: "); printBuffer(buffer, readrs);
			packet = new SVCPacket(buffer, readrs);
			packet->pushCommandParam((uint8_t*)&srcAddr, (uint16_t)srcAddrLen);
			daemonInetIncomingQueue->enqueue(packet);
		}
	}	
	free(buffer);
	pthread_exit(EXIT_SUCCESS);
}

void shutdown(){
	if (working){
		working = false;
		for (auto& it : endpoints){
			if (it.second != NULL){
				DaemonEndpoint* ep = (DaemonEndpoint*)it.second;
				endpoints.erase(ep->endpointID);
				delete ep; //-- destructor calls shutdown
			}
		}
		printf("\nstopping main threads"); fflush(stdout);
		//--	stop main threads
		daemonUnixIncomingPacketHandler->stopWorking();
		daemonUnixOutgoingPacketHandler->stopWorking();
		daemonInetIncomingPacketHandler->stopWorking();
		endpointChecker->stopWorking();
		
		printf("\nmain threads stopped"); fflush(stdout);
		//--	do cleanup before exit
		unlink(SVC_DAEMON_PATH.c_str());		
	}
}

void signal_handler(int sig){
	if (sig == SIGINT){
		printf("\nSIGINT caught, calling shutdown");
		shutdown();
	}	
}

void daemon_unix_incoming_packet_handler(SVCPacket* packet, void* args){
	uint8_t infoByte = packet->packet[INFO_BYTE];
	if ((infoByte & SVC_COMMAND_FRAME) != 0x00){
		enum SVCCommand cmd = (enum SVCCommand)packet->packet[CMD_BYTE];
		uint64_t endpointID = *((uint64_t*)packet->packet);
		bool existed = false;
		switch (cmd){
			case SVC_CMD_CREATE_ENDPOINT:
				printf("\nSVC_CMD_CREATE_ENDPOINT received for: "); printBuffer((uint8_t*)&endpointID, ENDPOINTID_LENGTH); fflush(stdout);				
				//-- check if this endpointID is used before to create an endpoint that is working				
				for (auto& it : endpoints){
					if (it.second != NULL){
						DaemonEndpoint* ep = (DaemonEndpoint*)it.second;
						if (endpointID == (ep->endpointID & 0x0000FFFFFFFFFFFF)){
							existed = true;
							break;
						}
					}
				}
				if (!existed){
					DaemonEndpoint* endpoint;
					try{
						endpoint = new DaemonEndpoint(endpointID);
						printf("\ntrying connect to app socket"); fflush(stdout);
						if (endpoint->connectToAppSocket()==0){
							endpoints[endpointID] = endpoint;
							//-- send back the packet
							//printf("\nenqueue the packet"); fflush(stdout);
							endpoint->unixOutgoingQueue->enqueue(packet);
							//-- add this endpoint to collection
							endpoints[endpointID] = endpoint;
						}
						else{
							delete packet;
							delete endpoint;
						}
					}
					catch(const char* err){
						printf("\nError: %s; remove SVC_CMD_CREATE_ENDPOINT packet", err); fflush(stdout);
						delete packet;
					}
				}
				else{
					//-- TODO: check if the endpoint has been dead, then replace
					printf("\nError: endpoint with the sameID is working");					
					delete packet;
				}
				break;
			
			default:
				delete packet;
				break;
		}
	}
	else{
		//-- ingore data frame
		delete packet;
	}
}

void daemon_unix_outgoing_packet_handler(SVCPacket* packet, void* args){
	
}

void daemon_inet_incoming_packet_handler(SVCPacket* packet, void* args){

	uint8_t infoByte = packet->packet[INFO_BYTE];	
	uint64_t endpointID = *((uint64_t*)packet->packet);	
	if ((infoByte & SVC_COMMAND_FRAME) != 0x00){
		//-- incoming command			
		enum SVCCommand cmd = (enum SVCCommand)packet->packet[CMD_BYTE];			
		uint64_t newEndpointID = 0;
		uint8_t* const param = (uint8_t*)malloc(SVC_DEFAULT_BUFSIZ);
		uint16_t paramLen;
		uint32_t appID;
		string appSockPath;
		DaemonEndpoint* dmnEndpoint;
	
		struct sockaddr_in sourceAddr;
		socklen_t sourceAddrLen;
		//-- extract source address
		packet->popCommandParam(param, &paramLen);
		memcpy(&sourceAddr, param, paramLen);
		sourceAddrLen = paramLen;		
		//-- TODO: check if this address is the same as connected, if not updates
				
		struct sockaddr_un appSockAddr;	
		memset(&appSockAddr, 0, sizeof(appSockAddr));
		appSockAddr.sun_family = AF_LOCAL;
		
		int sendrs;
	
		switch (cmd){
			case SVC_CMD_CONNECT_OUTER1:
				printf("\nSVC_CMD_CONNECT_OUTER1 received"); fflush(stdout);
				newEndpointID |= ++daemonEndpointCounter;
				newEndpointID <<= 48;
				newEndpointID |= endpointID;
				//-- create new daemonEndpoint for this endpointID
				dmnEndpoint = new DaemonEndpoint(newEndpointID);
				printf("\nendpoint created with ID: "); printBuffer((uint8_t*)&newEndpointID, ENDPOINTID_LENGTH);
				endpoints[newEndpointID] = dmnEndpoint;				
				dmnEndpoint->connectToAddress(&sourceAddr, sourceAddrLen);
				//-- extract DH-1
				packet->popCommandParam(param, &paramLen);
				dmnEndpoint->encryptedECPoint = new SVCPacket(param, paramLen);
				//-- extract appID
				packet->popCommandParam(param, &paramLen);
				//-- send the packet to the corresponding app
				packet->switchCommand(SVC_CMD_CONNECT_INNER2);			
				appID = *((uint32_t*)param);
				appSockPath = string(SVC_CLIENT_PATH_PREFIX) + to_string(appID);			
				memcpy(appSockAddr.sun_path, appSockPath.c_str(), appSockPath.size());
				//-- replace the oldEndpointID by the newEndpointID
				memcpy(packet->packet, (uint8_t*)&newEndpointID, ENDPOINTID_LENGTH);
				sendrs = sendto(daemonUnSocket, packet->packet, packet->dataLen, 0, (struct sockaddr*)&appSockAddr, sizeof(appSockAddr));
				delete packet;					
				break;
			
			case SVC_CMD_CONNECT_OUTER2:
				//-- newEndpointID contains old ID			
				newEndpointID = endpointID;
				endpointID = newEndpointID & 0x0000FFFFFFFFFFFF;			
				if (endpoints[endpointID] != NULL){				
					endpoints[newEndpointID] = endpoints[endpointID];
					//-- remove old record
					endpoints[endpointID] = NULL;
					//--	update endpointID
					endpoints[newEndpointID]->endpointID = newEndpointID;
					
					//-- forward packet
					endpoints[newEndpointID]->unixIncomingQueue->enqueue(packet);
				}
				else{
					delete packet;
				}
				break;
			
			default:			
				if (endpoints[endpointID] != NULL){
					//-- forward packet if endpoint found
					endpoints[endpointID]->unixIncomingQueue->enqueue(packet);
				}
				else{
					delete packet;
				}
				break;
		}			
		free(param);
	}
	else{
		//-- incoming data
		if (endpoints[endpointID] == NULL){
			//-- remove packet if endpoint not found
			delete packet;
		}
		else{
			//forward packet to inetIncomingQueue
			endpoints[endpointID]->inetIncomingQueue->enqueue(packet);
		}
	}
}

void checkEndpointLiveTime(void* args){	
	for (auto& it : endpoints){		
		if (it.second != NULL){
			DaemonEndpoint* ep = (DaemonEndpoint*)it.second;
			if ((!ep->working) || !(ep->isAuthenticated() || ep->checkInitLiveTime(1000))){
				//-- remove this endpoint, also remove it from endpoints
				printf("\nendpoints remove id: "); printBuffer((uint8_t*)&ep->endpointID, ENDPOINTID_LENGTH);
				endpoints[ep->endpointID] = NULL;				
				delete ep;
			}
		}
	}
}

int main(int argc, char** argv){
	
	string errorString;
	working = true;
	
	//-- block all signals, except SIGINT
    sigset_t blockSignals;
    sigfillset(&blockSignals);
    sigdelset(&blockSignals, SIGINT);    
    pthread_sigmask(SIG_SETMASK, &blockSignals, NULL);
	
	daemonUnixIncomingQueue = new MutexedQueue<SVCPacket*>();
	daemonUnixOutgoingQueue = new MutexedQueue<SVCPacket*>();
	daemonInetIncomingQueue = new MutexedQueue<SVCPacket*>();
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	
	//--	create a daemon unix socket and bind
	daemonUnSocket = socket(AF_LOCAL, SOCK_DGRAM, 0);
	memset(&daemonSockUnAddress, 0, sizeof(daemonSockUnAddress));
	daemonSockUnAddress.sun_family = AF_LOCAL;
	memcpy(daemonSockUnAddress.sun_path, SVC_DAEMON_PATH.c_str(), SVC_DAEMON_PATH.size());			
	if (bind(daemonUnSocket, (struct sockaddr*) &daemonSockUnAddress, sizeof(daemonSockUnAddress)) == -1) {		
		errorString = SVC_ERROR_BINDING;
        goto errorInit;
    }
    //-- then create a reading thread
	if (pthread_create(&daemonUnixReadingThread, &attr, daemon_unix_reading_loop, NULL) != 0){
		errorString = SVC_ERROR_CRITICAL;
		goto error;
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
    	goto error;
    }
    //-- then create a reading thread
	if (pthread_create(&daemonInetReadingThread, &attr, daemon_inet_reading_loop, NULL) != 0){
		errorString = SVC_ERROR_CRITICAL;
		goto error;
	}

    
    //-- handle SIGINT
	struct sigaction act;
	act.sa_handler = signal_handler;
	sigfillset(&act.sa_mask);
	sigdelset(&act.sa_mask, SIGINT);
	sigaction(SIGINT, &act, NULL);
	
	//-- packet handler
    daemonUnixIncomingPacketHandler = new PacketHandler(daemonUnixIncomingQueue, daemon_unix_incoming_packet_handler, NULL);
    daemonUnixOutgoingPacketHandler = new PacketHandler(daemonUnixOutgoingQueue, daemon_unix_outgoing_packet_handler, NULL);	
    daemonInetIncomingPacketHandler = new PacketHandler(daemonInetIncomingQueue, daemon_inet_incoming_packet_handler, NULL);
	//--	create a thread to check for daemon endpoints' lives
	endpointChecker = new PeriodicWorker(1000, checkEndpointLiveTime, NULL);
	
	//--	init some globals variables
	
    goto initSuccess;
    
    error:
    	unlink(SVC_DAEMON_PATH.c_str());
    errorInit:
    	delete daemonUnixIncomingQueue;
    	delete daemonUnixOutgoingQueue;
    	delete daemonInetIncomingQueue;
    	exit(EXIT_FAILURE);
    	
    initSuccess:
		//--	POST-SUCCESS JOBS	--//		
		endpoints.clear();
    	printf("\nSVC daemon is running..."); fflush(stdout);
    	        	
        daemonUnixIncomingPacketHandler->waitStop();
        daemonUnixOutgoingPacketHandler->waitStop();
        daemonInetIncomingPacketHandler->waitStop();
    	endpointChecker->waitStop();
    	pthread_join(daemonUnixReadingThread, NULL);
    	pthread_join(daemonInetReadingThread, NULL);
        	
    	delete daemonUnixIncomingPacketHandler;
    	delete daemonUnixOutgoingPacketHandler;
    	delete daemonInetIncomingPacketHandler;
    	delete endpointChecker;
    	printf("\nSVC daemon stopped\n");
    	return 0;
}


