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
bool working;

class DaemonEndpoint{
	public:
		//-- static methods
		static void dmn_endpoint_command_handler(SVCPacket* packet, void* args);
		
		//-- private members
		volatile bool working;
		bool isAuth;
		int initLiveTime;
		int dmnSocket;
		string dmnSockPath;
		struct sockaddr_in remoteAddr;
		size_t remoteAddrLen;
		PacketHandler* packetHandler;
		
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
		int sendPacketIn(SVCPacket* packet);
		int sendPacketOut(SVCPacket* packet);
		bool checkInitLiveTime(int interval);
		bool isAuthenticated();
		
		int connectToAppSocket();
		void encryptPacket(SVCPacket* packet);
		void decryptpacket(SVCPacket* packet);
		void connectToAddress(uint32_t remoteAddress);
		void connectToAddress(const struct sockaddr_in* sockAddr, socklen_t sockLen);
		
		void shutdown();
};

DaemonEndpoint::DaemonEndpoint(uint64_t endpointID){
	
	this->working = false;
	this->endpointID = endpointID;	
	this->isAuth = false;
	this->initLiveTime = SVC_ENDPOINT_LIVETIME;
	this->sendSequence = 0;
	this->recvSequence = 0;
	this->sendSequenceMutex = new SharedMutex();
	this->recvSequenceMutex = new SharedMutex();
	
	this->aesgcm = NULL;
	this->sha256 = new SHA256();
	
	//-- create dmn unix socket, bind 
	this->dmnSocket = socket(AF_LOCAL, SOCK_DGRAM, 0);
	struct sockaddr_un dmnSockAddr;
	this->dmnSockPath = SVC_ENDPOINT_DMN_PATH_PREFIX + hexToString((uint8_t*)&endpointID, ENDPOINTID_LENGTH);
	memset(&dmnSockAddr, 0, sizeof(dmnSockAddr));
	dmnSockAddr.sun_family = AF_LOCAL;
	memcpy(dmnSockAddr.sun_path, this->dmnSockPath.c_str(), dmnSockPath.size());
	
	if (bind(this->dmnSocket, (struct sockaddr*) &dmnSockAddr, sizeof(dmnSockAddr)) == -1){
		delete this->sha256;
		delete sendSequenceMutex;
		delete recvSequenceMutex;
		throw SVC_ERROR_BINDING;
	}
	else{
		//-- create a packet handler
		this->working = true;
		this->packetHandler = new PacketHandler(this->dmnSocket);
		this->packetHandler->setCommandHandler(dmn_endpoint_command_handler, this);
	}
}

void DaemonEndpoint::shutdown(){
	//printf("\nendpoint shutdown called with this = NULL?: %d ", this == NULL); printBuffer((uint8_t*)&this->endpointID, ENDPOINTID_LENGTH);fflush(stdout);
	if (this->working){
		//printf("\ninside this->working check"); fflush(stdout);
		this->working = false;
		
		//-- clean up
		delete sendSequenceMutex;
		delete recvSequenceMutex;
		delete this->sha256;
		delete this->packetHandler;
		unlink(this->dmnSockPath.c_str());
	}	
}

DaemonEndpoint::~DaemonEndpoint(){	
	shutdown();
}

int DaemonEndpoint::connectToAppSocket(){
	//-- then connect to app socket
	struct sockaddr_un appSockAddr;
	string appSockPath = SVC_ENDPOINT_APP_PATH_PREFIX + hexToString((uint8_t*)&endpointID, ENDPOINTID_LENGTH);
	memset(&appSockAddr, 0, sizeof(appSockAddr));
	appSockAddr.sun_family = AF_LOCAL;
	memcpy(appSockAddr.sun_path, appSockPath.c_str(), appSockPath.size());
	return connect(this->dmnSocket, (struct sockaddr*) &appSockAddr, sizeof(appSockAddr));
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

int DaemonEndpoint::sendPacketIn(SVCPacket* packet){
	return this->packetHandler->sendPacket(packet);
}

int DaemonEndpoint::sendPacketOut(SVCPacket* packet){
	//add sequence number to packet
	this->sendSequenceMutex->lock();
	this->sendSequence += 1;
	memcpy(packet->packet + ENDPOINTID_LENGTH + 1, (uint8_t*)&this->sendSequence, SEQUENCE_LENGTH);
	this->sendSequenceMutex->unlock();
	return sendto(daemonInSocket, packet->packet,packet->dataLen, 0, (struct sockaddr*)&this->remoteAddr, this->remoteAddrLen);	
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
			_this->shutdown();
			break;
			
		case SVC_CMD_CONNECT_INNER1:
			if (!_this->isAuth){
				//printf("\nreceived packet: "); printBuffer(packet->packet, packet->dataLen);
				printf("\nSVC_CMD_CONNECT_INNER1 received");			
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
				delete aeskey;
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
				delete ecpointHexString;
				
				ecpointHexString = mpz_get_str(NULL, 16, ecpoint->y);
				ecpointHexLen = strlen(ecpointHexString)+1; 
				//printf("\nsent gx_y: %s", ecpointHexString); fflush(stdout);
				memcpy(param + paramLen, &ecpointHexLen, 2);
				paramLen += 2;				
				memcpy(param+paramLen, ecpointHexString, ecpointHexLen);
				paramLen += ecpointHexLen;								
				delete ecpointHexString;				
				
				aes256->encrypt(param, paramLen, &encrypted, &encryptedLen);
				//printf("\nsent encrypted gx: "); printBuffer(encrypted, encryptedLen);
								
				//-- attach Ex(k1) to packet
				packet->pushCommandParam(encrypted, encryptedLen);
				delete encrypted;
				
				//-- switch commandID
				packet->switchCommand(SVC_CMD_CONNECT_OUTER1);
				//-- sent the packet
				_this->sendPacketOut(packet);
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
			delete aeskey;
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
				delete data;
				//-- extract challengeSecret y
				packet->popCommandParam(param, &paramLen);
				//-- use SHA256(y) as an AES256 key
				hashValue = _this->sha256->hash(string((char*)param, paramLen));
				//-- create new aes key to encrypt
				stringToHex(hashValue, &aeskey);
				delete aes256;
				aes256 = new AES256(aeskey);
				//printf("\naeskey used to encrypt gy: ");printBuffer(aeskey, KEY_LENGTH);
				delete aeskey;
				
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
				delete ecpointHexString;
				
				ecpointHexString = mpz_get_str(NULL, 16, _this->gxy->x);
				ecpointHexLen = strlen(ecpointHexString);
				memcpy(param + paramLen , ecpointHexString, ecpointHexLen);
				paramLen += ecpointHexLen;
				delete ecpointHexString;
				
				if (_this->aesgcm == NULL){
					//-- aesgcm key = hash(gxy.x || gxy.y)
					hashValue = _this->sha256->hash(string((char*)param, paramLen));
					stringToHex(hashValue, &aeskey);
					_this->aesgcm = new AESGCM(aeskey, (enum SecurityParameter)requested_security_strength);
					//-- free this memory
					//printf("\naesgcm key: "); printBuffer(aeskey, KEY_LENGTH);
					delete aeskey;
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
				delete encrypted;			
				
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
				delete encrypted;
				delete tag;
				
				//-- send out this packet
				_this->sendPacketOut(packet);
			}
			else{
				//-- decryted gx is damaged, delete data
				delete data;
			}
			break;
			
		case SVC_CMD_CONNECT_OUTER2:
			printf("\nSVC_CMD_CONNECT_OUTER2 received");			
			//-- pop encrypted proof
			packet->popCommandParam(param, &paramLen);
			_this->encryptedProof = new SVCPacket(param, paramLen);
			//printf("\nencrypted proof received by printBuffer: "); printBuffer(param, paramLen);			
			
			packet->popCommandParam(param, &paramLen);
			_this->encryptedECPoint = new SVCPacket(param, paramLen);
			
			//-- change command to INNER_4
			packet->switchCommand(SVC_CMD_CONNECT_INNER4);
			//-- app svc is still waiting for the 'old' endpointID, push the current endpointID as new param
			packet->pushCommandParam(packet->packet, ENDPOINTID_LENGTH);
			//-- clear the 6&7 byte of endpointID
			packet->packet[6]=0x00;
			packet->packet[7]=0x00;
			_this->sendPacketIn(packet);			
			break;
			
		case SVC_CMD_CONNECT_INNER5:
			printf("\nSVC_CMD_CONNECT_INNER5 received");
			printf("\npacket: "); printBuffer(packet->packet, packet->dataLen);
			packet->popCommandParam(param, &paramLen);
			//solution = string((char*)param, paramLen);
			//printf("\ndmn Endpoint received solution: %s", solution.c_str()); fflush(stdout);
			
			//-- hash this solution to create the aes256 key to decrypt encryptedECPoint from CONNECT_OUTER2
			hashValue = _this->sha256->hash(string((char*)param, paramLen));
			stringToHex(hashValue, &aeskey); //-- aes key used to decrypt k1
			aes256 = new AES256(aeskey);
			//printf("\naeskey used to decrypt gy: "); printBuffer(aeskey, KEY_LENGTH);
			delete aeskey;
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
				delete data;
				//-- generate shared secret gxy
				_this->gxy = _this->curve->mul(ecpoint, &_this->randomX);
				
				//-- generate aesgcm to decrypt solution proof
				ecpointHexString = mpz_get_str(NULL, 16, _this->gxy->x);
				ecpointHexLen = strlen(ecpointHexString);
				memcpy(param, ecpointHexString, ecpointHexLen);
				paramLen = ecpointHexLen;
				delete ecpointHexString;
				
				ecpointHexString = mpz_get_str(NULL, 16, _this->gxy->x);
				ecpointHexLen = strlen(ecpointHexString);
				memcpy(param + paramLen , ecpointHexString, ecpointHexLen);
				paramLen += ecpointHexLen;
				delete ecpointHexString;
				
				if (_this->aesgcm == NULL){
					//-- aesgcm key = hash(gxy.x || gxy.y)
					hashValue = _this->sha256->hash(string((char*)param, paramLen));
					stringToHex(hashValue, &aeskey);
					//printf("\naesgcm key: "); printBuffer(aeskey, KEY_LENGTH);
					_this->aesgcm = new AESGCM(aeskey, (enum SecurityParameter)requested_security_strength);
					//-- free this memory
					delete aeskey;
					
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
						//printf("\nsend inner6 result: %d ", _this->sendPacketIn(packet));
						delete data;
					}
					else{
						printf("\naesgcm decrypt failed");
					}					
				}
				//--	else: _this->aesgcm is not null			
			}
			else{				
				//printf("\ndecrypted gy damaged, delete data");
				delete data;
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
			_this->sendPacketOut(packet);
			delete encrypted;
			delete tag;
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
				sendrs = _this->sendPacketIn(packet);
				//printf("\nsend this CONNECT_INNER8 to app %d %d: ", sendrs, errno); printBuffer(packet->packet, packet->dataLen); fflush(stdout);
				delete data;
			}
			else{
				printf("\naesgcm decrypt failed");
			}
			break;
			
		case SVC_CMD_CONNECT_INNER9:
			//-- connection established
			printf("\nSVC_CMD_CONNECT_INNER9 received"); fflush(stdout);
			_this->isAuth = true;
			break;
			
		default:
			break;
	}
	delete packet;
	delete param;
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
		//--	stop main threads
		inPacketHandler->stopWorking();
		unPacketHandler->stopWorking();
		endpointChecker->stopWorking();
		//--	do cleanup before exit
		unlink(SVC_DAEMON_PATH.c_str());		
	}
}

void signal_handler(int sig){
	if (sig == SIGINT){
		shutdown();
	}	
}

void daemonUnCommandHandler(SVCPacket* packet, void* args){	
	enum SVCCommand cmd = (enum SVCCommand)packet->packet[SVC_PACKET_HEADER_LEN];
	uint64_t endpointID = *((uint64_t*)packet->packet);
	switch (cmd){
		case SVC_CMD_CREATE_ENDPOINT:
			//-- check if the endpoint already exists
			printf("\nSVC_CMD_CREATE_ENDPOINT received for: "); printBuffer((uint8_t*)&endpointID, ENDPOINTID_LENGTH); fflush(stdout);		
			if (endpoints[endpointID]==NULL){		
				DaemonEndpoint* endpoint = new DaemonEndpoint(endpointID);				
				endpoint->connectToAppSocket();
				endpoints[endpointID] = endpoint;
				//-- send back the packet
				endpoint->sendPacketIn(packet);
			}
			break;
			
		default:
			break;
	}
	delete packet;
}

void daemonInCommandHandler(SVCPacket* packet, void* args){
	enum SVCCommand cmd = (enum SVCCommand)packet->packet[SVC_PACKET_HEADER_LEN];
	uint64_t endpointID = *((uint64_t*)packet->packet);
	uint64_t newEndpointID = 0;
	uint8_t* const param = (uint8_t*)malloc(SVC_DEFAULT_BUFSIZ);
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
			printf("\nSVC_CMD_CONNECT_OUTER1 received"); fflush(stdout);
			newEndpointID |= ++daemonEndpointCounter;
			newEndpointID <<= 48;
			newEndpointID |= endpointID;
			//-- create new daemonEndpoint for this endpointID
			dmnEndpoint = new DaemonEndpoint(newEndpointID);
			printf("\nendpoint created with ID: "); printBuffer((uint8_t*)&newEndpointID, ENDPOINTID_LENGTH);
			endpoints[newEndpointID] = dmnEndpoint;
			//-- extract source address
			packet->popCommandParam(param, &paramLen);
			memcpy(&sourceAddr, param, paramLen);
			sourceAddrLen = paramLen;
			dmnEndpoint->connectToAddress(&sourceAddr, sourceAddrLen);
			//-- extract DH-1
			packet->popCommandParam(param, &paramLen);
			dmnEndpoint->encryptedECPoint = new SVCPacket(param, paramLen);
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
			printf("\nSVC_CMD_CONNECT_OUTER2 received"); fflush(stdout);
			//-- newEndpointID contains old ID			
			newEndpointID = endpointID;
			endpointID = newEndpointID & 0x0000FFFFFFFFFFFF;			
			if (endpoints[endpointID] != NULL){
				endpoints[newEndpointID] = endpoints[endpointID];
				//-- remove old record
				endpoints.erase(endpointID);
				//--	update endpointID
				endpoints[newEndpointID]->endpointID = newEndpointID;
				//-- forward packet
				DaemonEndpoint::dmn_endpoint_command_handler(packet, endpoints[newEndpointID]);
			}
			break;
			
		default:			
			if (endpoints[endpointID] != NULL){
				//-- forward packet if endpoint found
				DaemonEndpoint::dmn_endpoint_command_handler(packet, endpoints[endpointID]);
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
	//uint64_t id;
	//unordered_map<uint64_t, DaemonEndpoint*>::iterator const it = endpoints.begin();
	for (auto it = endpoints.begin(); it!= endpoints.end();){
		//id = it->first;
		//printf("\ncheck live time call destructor for: "); printBuffer((uint8_t*)&id, ENDPOINTID_LENGTH); fflush(stdout);
		if (it->second != NULL){
			DaemonEndpoint* ep = (DaemonEndpoint*)it->second;
			if ((!ep->working) || !(ep->isAuthenticated() || ep->checkInitLiveTime(1000))){
				//-- remove this endpoint, also remove it from endpoints
				//printf("\nendpoints remove id: "); printBuffer((uint8_t*)&ep->endpointID, ENDPOINTID_LENGTH);
				it = endpoints.erase(it);				
				delete ep;
			}
			else{
				it++;
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
		working = true;
		endpoints.clear();
    	printf("\nSVC daemon is running...");
    	fflush(stdout);
    	
        inPacketHandler->waitStop();
    	unPacketHandler->waitStop();    	
    	endpointChecker->waitStop();    	
    	
    	delete inPacketHandler;
    	delete unPacketHandler;
    	delete endpointChecker;
    	//-- wait here until signal caught    	
    	printf("\nSVC daemon stopped\n");
    	return 0;
}


