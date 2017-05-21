#include <thread>
#include <mutex>
#include <condition_variable>
#include <errno.h>
#include <iostream>
#include <fstream>
#include <string>
#include <exception>
#include <unordered_map>

#include "svc-header.h"
#include "svc-utils.h"
#include "../utils/NamedPipe.h"
#include "../utils/HTPSocket.h"

#include "../crypto/crypto-utils.h"
#include "../crypto/SHA256.h"
#include "../crypto/ECCurve.h"
#include "../crypto/AESGCM.h"

using namespace std;
using namespace svc_utils;

//================================ TYPE DEFINITION =================
class SVCDaemonConfig{
	public:
		uint8_t networkType;
		string localHost;
		int daemonPort;		//-- specific in INET network

		SVCDaemonConfig(){
			localHost = "";
		}

		~SVCDaemonConfig(){}

		SVCDaemonConfig* clone(){
			SVCDaemonConfig* result = new SVCDaemonConfig();
			result->networkType = this->networkType;
			result->localHost = this->localHost;
			result->daemonPort = this->daemonPort;
			return result;
		}
};

class SVCDaemonImage{
	public:
		SVCDaemonConfig* config;
};


class SVCClient{
	public:
		bool working;
		uint64_t pipeID;
		NamedPipe* pipe;
		uint32_t appID;

		SVCClient(){
			this->working = true;
		}

		~SVCClient(){
			if (this->pipe != NULL){
				delete this->pipe;
			}
		}
};

class STSNegotiation{
	public:
		bool isEstablished;
		uint32_t sequence;

		bool internalRandomX;
		ECCurve* ecCurve;
		mpz_t randomX;
		mpz_t randomY;
		ECPoint* gx;
		ECPoint* gy;
		ECPoint* gxy;
		AESGCM* aesGCM;
		int requested_security_strength;
		SHA256* sha256;


		STSNegotiation(){
			this->sha256 = new SHA256();
			this->aesGCM = NULL;
			this->gx = NULL;
			this->gy = NULL;
			this->sequence = 2;
			mpz_init(this->randomX);
			mpz_init(this->randomY);
			this->ecCurve = new ECCurve();
			this->requested_security_strength = this->ecCurve->getRequestSecurityLength();
		}

		void generateGx(){
			this->internalRandomX = true;			
			crypto::generateRandomNumber(&this->randomX, this->requested_security_strength);
			this->gx = new ECPoint();
			this->ecCurve->mul(this->gx, this->ecCurve->g, &this->randomX);
		}

		void generateGy(){
			this->internalRandomX = false;
			crypto::generateRandomNumber(&this->randomY, this->requested_security_strength);
			this->gy = new ECPoint();
			this->ecCurve->mul(this->gy, this->ecCurve->g, &this->randomY);
		}


		void setGx(const mpz_t* x, const mpz_t* y){
			this->gx = new ECPoint(x, y);
		}

		void setGy(const mpz_t* x, const mpz_t* y){
			this->gy = new ECPoint(x, y);
		}

		void generateGxy(){
			this->gxy = new ECPoint();
			if (this->internalRandomX){
				this->ecCurve->mul(this->gxy, this->gy, &(this->randomX));
			}
			else{
				this->ecCurve->mul(this->gxy, this->gx, &(this->randomY));
			}

			//-- create aesGCM based on this key
			uint8_t buffer[2*sizeof(mpz_t)];
			memcpy(buffer, &(this->gxy->x), sizeof(mpz_t));
			memcpy(buffer + sizeof(mpz_t), &(this->gxy->y), sizeof(mpz_t));
			uint8_t hashResult[32];
			this->sha256->hash(buffer, 2*sizeof(mpz_t), hashResult);
			this->aesGCM = new AESGCM(hashResult, (enum SecurityParameter)this->requested_security_strength);
		}

		void encryptPacket(SVCPacket* packet){
			this->sequence++;

			//-- TODO: check if sequence > 2^31 then negotiate a new session

			uint8_t packetBody[SVC_DEFAULT_BUFSIZ];
			uint16_t packetBodyLen;

			packet->popDataChunk(packetBody, &packetBodyLen);

			uint8_t* iv = (uint8_t*)&this->sequence;
			uint16_t ivLen = SEQUENCE_LENGTH;	
			
			uint8_t* tag;
			uint16_t tagLen;	
			uint8_t* encrypted;
			uint32_t encryptedLen;

			//-- set infoByte
			packet->setInfoByte(packet->getInfoByte() | SVC_ENCRYPTED);
			
			//cout<<"\nencrypt packet with:");
			//cout<<"\niv: "); printBuffer(iv, ivLen); fflush(stdout);
			//cout<<"\naad: "); printBuffer(packet->packet, SVC_PACKET_HEADER_LEN); fflush(stdout);
			//cout<<"\ndata: "); printBuffer(packet->packet+SVC_PACKET_HEADER_LEN, packet->dataLen); fflush(stdout);
			
			
			this->aesGCM->encrypt(iv, ivLen, packetBody, packetBodyLen, packet->packetHeader, SVC_PACKET_HEADER_LEN, &encrypted, &encryptedLen, &tag, &tagLen);
			
			//cout<<"\ngot:");
			//cout<<"\nencrypted: "); printBuffer(encrypted, encryptedLen); fflush(stdout);
			//cout<<"\ntag: "); printBuffer(tag, tagLen); fflush(stdout);
			
			packet->pushDataChunk(encrypted, encryptedLen);
			packet->pushDataChunk(tag, tagLen);	
			
			free(encrypted);
			free(tag);
		}

		bool decryptPacket(SVCPacket* packet){
			bool rs;
			uint32_t iv = packet->getSequence();
			
			uint8_t packetTag[SVC_DEFAULT_BUFSIZ];
			uint16_t packetTagLen;
			uint8_t packetEncrypted[SVC_DEFAULT_BUFSIZ];
			uint16_t packetEncryptedLen;
			
			uint8_t* decrypted;
			uint32_t decryptedLen;

			packet->popDataChunk(packetTag, &packetTagLen);
			packet->popDataChunk(packetEncrypted, &packetEncryptedLen);
			
				
			//cout<<"\ndecrypt packet with:");
			//cout<<"\niv: "); printBuffer(iv, ivLen); fflush(stdout);
			//cout<<"\naad: "); printBuffer(aad, aadLen); fflush(stdout);
			//cout<<"\ntag: "); printBuffer(tag, tagLen); fflush(stdout);
			//cout<<"\nencrypted: "); printBuffer(packet->packet+SVC_PACKET_HEADER_LEN, packet->dataLen); fflush(stdout);
			
			rs = this->aesGCM->decrypt((uint8_t*)&iv, SEQUENCE_LENGTH, packetEncrypted, packetEncryptedLen, packet->packetHeader, SVC_PACKET_HEADER_LEN, packetTag, packetTagLen, &decrypted, &decryptedLen);
			
			//cout<<"\ngot:");
			//cout<<"\ndecrypted: "); printBuffer(decrypted, decryptedLen); fflush(stdout);
				
			//-- set body to be decrypted
			if (rs){
				packet->pushDataChunk(decrypted, decryptedLen);
				packet->setInfoByte(packet->getInfoByte() & ~SVC_ENCRYPTED);
			}
			free(decrypted);
			return rs;
		}

		~STSNegotiation(){
			mpz_clear(randomX);
			mpz_clear(randomY);
			delete this->ecCurve;
			delete this->gx;
			delete this->gy;
			delete this->gxy;
			delete this->aesGCM;
		}

};

class DaemonEndpoint;


//================================= GLOBAL CONSTANT  ===============
const string ARG_DEFAULT_CONFIG = "--default-config";
const string ARG_HELP = "--help";
const string ARG_START = "--start";
const string ARG_SHUTDOWN = "--stop";
const string ARG_CONFIG = "-c";
const string ARG_IMAGE = "-i";
const string ARG_CONFIG_PATH = "config_file_path";
const string ARG_IMAGE_PATH = "image_file_path";
const string svcDefaultConfigFilename = "svcdaemon.conf";

SVCDaemonConfig* svcDefaultConfig;

//================================= GLOBAL VARIABLE ================
NamedPipe* daemonLocalPipe;
HTPSocket* htpSocket;

MutexedQueue<SVCPacket*>* localIncomingQueue;
SVCPacketReader* localPacketReader;
SVCPacketHandler* localPacketHandler;

MutexedQueue<SVCPacket*>* netIncomingQueue;
SVCPacketReader* netPacketReader;
SVCPacketHandler* netPacketHandler;

SVCDaemonConfig* daemonConfig;

mutex stopMutex;
condition_variable stopCV;
bool working;

//-- svcClients indexed by pipeID
unordered_map<uint64_t, SVCClient*> svcClients;
//-- indexed by pipeID
unordered_map<uint64_t, DaemonEndpoint*> daemonEndpointsByPipeID;
//-- indexed by sessionID 
unordered_map<uint64_t, DaemonEndpoint*> daemonEndpointsBySessionID;

//================================= DAEMON FUNCTIONS' DECLARATION ===========
void waitStop();
int exitWithError(string err);
int showHelp();
int startDaemon(SVCDaemonImage* image);
int shutdownDaemon(bool saveImage, const string& imagePath);
int saveDefaultConfig(const string& configPath);
bool loadConfig(const string& filename, SVCDaemonConfig* config);
bool loadImage(const string& filename, SVCDaemonImage** image);
void shutdown();
void loadDefaults();
void unload();

void daemon_local_packet_handler(SVCPacket* packet, void* args);


class DaemonEndpoint{
	public:
		SVCClient* svcClient;
		uint8_t option;
		uint64_t pipeID;
		uint64_t sessionID;
		HostAddr* hostAddr;
		STSNegotiation* sts;
		
		bool working;
		NamedPipe* readPipe;
		NamedPipe* writePipe;
		SVCPacketReader* localPacketReader;
		MutexedQueue<SVCPacket*>* localReadingQueue;
		SVCPacketHandler* localPacketHandler;

		MutexedQueue<SVCPacket*>* netReadingQueue;
		SVCPacketHandler* netPacketHandler;

		static void local_incoming_packet_handler(SVCPacket* packet, void* args){
			DaemonEndpoint* _this = (DaemonEndpoint*)args;

			uint8_t infoByte = packet->getInfoByte();
			if ((infoByte & SVC_COMMAND_FRAME) != 0x00){
				enum SVCCommand cmd = (enum SVCCommand)packet->getExtraInfoByte();
				switch (cmd){
					case SVC_CMD_SHUTDOWN_ENDPOINT:
						{
							//-- TODO: send SVC_CMD_SHUTDOWN_ENDPOINT to other end
							cout<<"received SVC_CMD_SHUTDOWN_ENDPOINT"<<endl;
							_this->shutdown();
							break;
						}

					case SVC_CMD_CONNECT_INNER1:
						{
							uint8_t param[SVC_DEFAULT_BUFSIZ];
							uint16_t paramLen;
							cout<<"received SVC_CMD_CONNECT_INNER1"<<endl;
							_this->sts->generateGx();					
							packet->pushDataChunk(&(_this->sts->gx->x), sizeof(mpz_t));
							packet->pushDataChunk(&(_this->sts->gx->y), sizeof(mpz_t));
							
							//-- switch commandID
							packet->setCommand(SVC_CMD_CONNECT_OUTER1);

							//-- generate first 32 bits of sessionID
							bool duplicatedID;
							do{
								duplicatedID = false;
								uint32_t firstHalf;
								crypto::generateRandomData(4, &firstHalf);
								//-- check for duplicate
								for (auto it = daemonEndpointsByPipeID.begin(); it!=daemonEndpointsByPipeID.end(); it++){
									DaemonEndpoint* endpoint = (DaemonEndpoint*)it->second;
									if (memcmp(&endpoint->sessionID, &firstHalf, 4) == 0){
										duplicatedID = true;
										break;
									}
								}
								if (!duplicatedID){
									memcpy(&_this->sessionID, &firstHalf, 4);
									packet->setEndpointID(_this->sessionID);
								}
							}
							while (duplicatedID);

							//-- add appID
							packet->pushDataChunk(&_this->svcClient->appID, APPID_LENGTH);

							//-- send the packet to internet
							packet->serialize(param, &paramLen);
							htpSocket->writeTo(_this->hostAddr, param, paramLen, 0);
							printf("send out SVC_CMD_CONNECT_OUTER1\n");
							break;
						}

					case SVC_CMD_CONNECT_INNER3:
						{
							cout<<"received SVC_CMD_CONNECT_INNER3"<<endl;
							uint8_t param[SVC_DEFAULT_BUFSIZ];
							uint16_t paramLen;

							_this->sts->generateGy();
							_this->sts->generateGxy();
							
							//-- pop proof
							packet->popDataChunk(param, &paramLen);

							//-- push Gy
							packet->pushDataChunk(&(_this->sts->gy->x), sizeof(mpz_t));
							packet->pushDataChunk(&(_this->sts->gy->y), sizeof(mpz_t));

							//-- encrypt proof
							uint32_t iv = 0;
							uint8_t* tag;
							uint16_t tagLen;	
							uint8_t* encrypted;
							uint32_t encryptedLen;
							_this->sts->aesGCM->encrypt((uint8_t*) &iv, 4, param, paramLen, NULL, 0, &encrypted, &encryptedLen, &tag, &tagLen);

							packet->pushDataChunk(encrypted, encryptedLen);
							packet->pushDataChunk(tag, tagLen);

							//-- free allocated buffers
							free(tag);
							free(encrypted);

							//-- switch commandID
							packet->setCommand(SVC_CMD_CONNECT_OUTER2);

							//-- send out
							packet->serialize(param, &paramLen);
							htpSocket->writeTo(_this->hostAddr, param, paramLen, 0);
							break;
						}

					case SVC_CMD_CONNECT_INNER5:
						{
							uint8_t param[SVC_DEFAULT_BUFSIZ];
							uint16_t paramLen;

							//-- pop proof
							packet->popDataChunk(param, &paramLen);

							//-- encrypt proof
							uint32_t iv = 1;
							uint8_t* tag;
							uint16_t tagLen;	
							uint8_t* encrypted;
							uint32_t encryptedLen;
							_this->sts->aesGCM->encrypt((uint8_t*) &iv, 4, param, paramLen, NULL, 0, &encrypted, &encryptedLen, &tag, &tagLen);

							packet->pushDataChunk(encrypted, encryptedLen);
							packet->pushDataChunk(tag, tagLen);

							//-- free allocated buffers
							free(tag);
							free(encrypted);

							//-- switch commandID
							packet->setCommand(SVC_CMD_CONNECT_OUTER3);

							//-- send out
							packet->serialize(param, &paramLen);
							htpSocket->writeTo(_this->hostAddr, param, paramLen, 0);
						}
						break;

					default:
						{
							break;
						}
				}
				delete packet;
			}
			else{
				uint8_t param[SVC_DEFAULT_BUFSIZ];
				uint16_t paramLen;
				//-- encrypt packet then send out
				_this->sts->encryptPacket(packet);
				packet->serialize(param, &paramLen);
				htpSocket->writeTo(_this->hostAddr, param, paramLen, 0);
			}
		}

		static void net_incoming_packet_handler(SVCPacket* packet, void* args){
			DaemonEndpoint* _this = (DaemonEndpoint*)args;

			uint8_t param[SVC_DEFAULT_BUFSIZ];
			uint16_t paramLen;

			uint8_t infoByte = packet->getInfoByte();
			if ((infoByte & SVC_COMMAND_FRAME) != 0x00){
				enum SVCCommand cmd = (enum SVCCommand)packet->getExtraInfoByte();
				switch (cmd){

					case SVC_CMD_CONNECT_OUTER1:
						{
							cout<<"received SVC_CMD_CONNECT_OUTER1"<<endl;

							//-- generate last 32 bits of sessionID
							bool duplicatedID;
							do{
								duplicatedID = false;
								uint32_t lastHalf;
								crypto::generateRandomData(4, &lastHalf);
								//-- check for duplicate
								for (auto it = daemonEndpointsByPipeID.begin(); it!=daemonEndpointsByPipeID.end(); it++){
									DaemonEndpoint* endpoint = (DaemonEndpoint*)it->second;
									if (memcmp(&endpoint->sessionID+4, &lastHalf, 4) == 0){
										duplicatedID = true;
										break;
									}
								}
								if (!duplicatedID){
									memcpy(&_this->sessionID+4, &lastHalf, 4);
									packet->setEndpointID(_this->sessionID);
									daemonEndpointsBySessionID[_this->sessionID] = _this;
								}
							}
							while (duplicatedID);

							_this->sts->setGx((mpz_t*)((*packet)[1]->chunk), (mpz_t*)((*packet)[0]->chunk));

							//-- pop out: gx.y, gx.y
							packet->popDataChunk();
							packet->popDataChunk();

							//-- switch commandID
							packet->setCommand(SVC_CMD_CONNECT_INNER2);

							//-- send the packet to client
							packet->serialize(param, &paramLen);
							_this->writePipe->write(param, paramLen, 0);
							break;
						}

					case SVC_CMD_CONNECT_OUTER2:
						{
							cout<<"received SVC_CMD_CONNECT_OUTER2"<<endl;

							//-- update sessionID
							_this->sessionID = packet->getEndpointID();
							//-- add reference to daemonEndpointsBySessionID
							daemonEndpointsBySessionID[_this->sessionID] = _this;

							//-- get Gy
							_this->sts->setGy((mpz_t*)(*packet)[3]->chunk, (mpz_t*)(*packet)[2]->chunk);

							//-- generate Gxy and the common key to create aesGCM
							_this->sts->generateGxy();

							//-- decrypt E_px
							uint32_t iv = 0;
							uint8_t* decrypted;
							uint32_t decryptedLen;
							if (_this->sts->aesGCM->decrypt((uint8_t*) &iv, SEQUENCE_LENGTH, (*packet)[1]->chunk, (*packet)[1]->chunkLen, NULL, 0, (*packet)[0]->chunk, (*packet)[0]->chunkLen, &decrypted, &decryptedLen)){
								
								//-- pop out: tag, encrypted proof, gy.y, gy.x
								packet->popDataChunk();
								packet->popDataChunk();
								packet->popDataChunk();
								packet->popDataChunk();

								//-- push Px
								packet->pushDataChunk(decrypted, decryptedLen);
								//-- send to client
								packet->setCommand(SVC_CMD_CONNECT_INNER4);
								packet->serialize(param, &paramLen);
								_this->writePipe->write(param, paramLen, 0);
							}
							else{
								//-- TODO: decrypt failed
							}
							free(decrypted);
							break;
						}

					case SVC_CMD_CONNECT_OUTER3:
						{
							cout<<"received SVC_CMD_CONNECT_OUTER3"<<endl;
							
							//-- decrypt E_py
							uint32_t iv = 0;
							uint8_t* decrypted;
							uint32_t decryptedLen;
							if (_this->sts->aesGCM->decrypt((uint8_t*) &iv, SEQUENCE_LENGTH, (*packet)[1]->chunk, (*packet)[1]->chunkLen, NULL, 0, (*packet)[0]->chunk, (*packet)[0]->chunkLen, &decrypted, &decryptedLen)){
								//-- pop out tag, encrypted Py
								packet->popDataChunk();
								packet->popDataChunk();

								//-- push Py
								packet->pushDataChunk(decrypted, decryptedLen);
								//-- send to client
								packet->setCommand(SVC_CMD_CONNECT_INNER6);
								packet->serialize(param, &paramLen);
								_this->writePipe->write(param, paramLen, 0);
							}
							else{
								//-- TODO: decrypt failed
							}
							free(decrypted);
							break;
						}		
	
					default:
						{
							break;
						}
				}
			}
			else{
				//-- decrypt packet then send to client
				if (_this->sts->decryptPacket(packet)){
					//-- send decrypted packet to client
					packet->serialize(param, &paramLen);
					_this->writePipe->write(param, paramLen, 0);
				}
				else{
					//-- TODO: decrypt failed, feedback to htp??
					//-- htpSocket->feedbackErrorPacket(...)
				}
			}
			delete packet;
		}

		DaemonEndpoint(SVCClient* svcClient, uint8_t option, uint64_t pipeID, HostAddr* hostAddr){
			this->svcClient = svcClient;
			this->option = option;
			this->pipeID = pipeID;
			this->hostAddr = hostAddr;
			this->sts = new STSNegotiation();
			memset(&this->sessionID, 0, ENDPOINTID_LENGTH);
			
			this->readPipe = new NamedPipe(SVC_DAEMON_ENDPOINT_PIPE_PREFIX + to_string(pipeID), NamedPipeMode::NP_READ);
			this->writePipe = new NamedPipe(SVC_ENDPOINT_PIPE_PREFIX + to_string(pipeID), NamedPipeMode::NP_WRITE);
			this->localReadingQueue = new MutexedQueue<SVCPacket*>();
			this->localPacketReader = new SVCPacketReader(this->readPipe, this->localReadingQueue, 0);
			this->localPacketHandler = new SVCPacketHandler(this->localReadingQueue, DaemonEndpoint::local_incoming_packet_handler, this);
			this->netReadingQueue = new MutexedQueue<SVCPacket*>();
			this->netPacketHandler = new SVCPacketHandler(this->netReadingQueue, DaemonEndpoint::net_incoming_packet_handler, this);
			this->working = true;
		}

		void shutdown(){
			if (this->working){
				this->working = false;
				this->writePipe->close();
				this->readPipe->close();
				this->localPacketReader->stopWorking();
				this->localReadingQueue->close();
				this->localPacketHandler->stopWorking();
				this->netReadingQueue->close();
				this->netPacketHandler->stopWorking();

				delete this->writePipe;
				delete this->readPipe;
				delete this->localPacketHandler;
				delete this->localPacketReader;
				delete this->localReadingQueue;
				delete this->netReadingQueue;
				delete this->netPacketHandler;
				delete this->hostAddr;
				delete this->sts;
				cout<<"endpoint: "<<this->pipeID<<" shutdown"<<endl;
			}
		}

		~DaemonEndpoint(){
			this->shutdown();
		}
};


//================================= MAIN =============================
int main(int argc, char* argv[]){

	//-- default values
	int ret;
	loadDefaults();

	//-- parse arguments
	if (argc == 1){
		ret = showHelp();
	}
	else{
		int i = 1;
		if (argv[i] == ARG_HELP){
			ret = showHelp();
		}
		else if (argv[i] == ARG_START){
			if (i+2 < argc){
				SVCDaemonImage* image;
				if (argv[i+1] == ARG_CONFIG){
					image = new SVCDaemonImage();
					if (loadConfig(string(argv[i+2]), image->config)){
						ret = startDaemon(image);
					}
					else{
						ret = exitWithError(ERR_NOCONFIG);
					}
				}
				else if (argv[i+1] == ARG_IMAGE){
					if (loadImage(string(argv[i+2]), &image)){
						ret = startDaemon(image);
					}
					else{
						ret = exitWithError(ERR_NOIMAGE);
					}
				}
				else {
					ret = exitWithError(ERR_PARAM);
				}
			}
			else if (i == argc-1){
				if (saveDefaultConfig(svcDefaultConfigFilename) == 0){
					SVCDaemonImage* image = new SVCDaemonImage();
					image->config = svcDefaultConfig;
					ret = startDaemon(image);
				}
				else{
					ret = exitWithError(ERR_PERM);
				}
			}
			else{
				ret = exitWithError(ERR_PARAM);
			}
		}
		else if (argv[i] == ARG_SHUTDOWN){
			if (i+2 < argc){
				if (argv[i+1] == ARG_IMAGE){
					ret = shutdownDaemon(true, argv[i+2]);
				}
				else{
					ret = exitWithError(ERR_PARAM);
				}
			}
			else if (i == argc-1){
				ret = shutdownDaemon(false, "");
			}
			else{
				ret = exitWithError(ERR_PARAM);
			}
		}
		else if (argv[i] == ARG_DEFAULT_CONFIG){
			if (i+1 < argc){
				ret = saveDefaultConfig(argv[i+1]);
			}
			else{
				ret = saveDefaultConfig(svcDefaultConfigFilename);
			}
		}
		else{
			ret = exitWithError(ERR_PARAM);
		}
	}
	unload();
	return ret;
}

//================================= DAEMMON FUNCTIONS' DEFINITION ====
void loadDefaults(){
	svcDefaultConfig = new SVCDaemonConfig();
	svcDefaultConfig->networkType = NETWORK_TYPE_IPv4;
	svcDefaultConfig->localHost = string("0.0.0.0:9293");
	svcDefaultConfig->daemonPort = 9293;
}

void unload(){
	delete svcDefaultConfig;
}

void daemon_local_packet_handler(SVCPacket* packet, void* args){
	uint8_t infoByte = packet->getInfoByte();
	if ((infoByte & SVC_COMMAND_FRAME) != 0x00){
		enum SVCCommand cmd = (enum SVCCommand)packet->getExtraInfoByte();
		switch (cmd){
			case SVC_CMD_STOP_DAEMON:
				{
					//-- check to save image
					uint8_t saveImage;
					packet->popDataChunk(&saveImage);
					if (saveImage){
						uint8_t imagePath[1024];
						memset(imagePath, 0, 1024);
						packet->popDataChunk(imagePath);
						string strImagePath = string((char*)imagePath);
						//-- TODO: pause all working instances and save their states to strImagePath
					}

					//-- send SVC_CMD_DAEMON_DOWN to all svc client
					SVCPacket* p = new SVCPacket();
					p->setCommand(SVC_CMD_DAEMON_DOWN);
					uint16_t bufferLen;
					uint8_t buffer[SVC_DEFAULT_BUFSIZ];
					p->serialize(buffer, &bufferLen);
					delete p;
					for (auto it = svcClients.begin(); it != svcClients.end(); it++){
						if (it->second != NULL){
							SVCClient* client = (SVCClient*)it->second;
							client->pipe->write(buffer, bufferLen, 0);
						}
					}
					
					stopMutex.lock();
					working = false;
					stopMutex.unlock();
					stopCV.notify_all();
					break;
				}
			
			case SVC_CMD_REGISTER_SVC:
				{
					uint16_t bufferLen;
					uint8_t buffer[SVC_DEFAULT_BUFSIZ];
					//-- check if the client has existed
					uint64_t pipeID = packet->getEndpointID();
					if (svcClients[pipeID] == NULL){
						if (packet->popDataChunk(buffer, &bufferLen)){
							uint32_t appID;
							memcpy(&appID, buffer, APPID_LENGTH);
							SVCClient* svcClient = new SVCClient();
							svcClient->appID = appID;
							cout<<"svc register with appID: "<<appID<<endl;
							try{
								string pipeName = to_string(pipeID);
								svcClient->pipeID = pipeID;
								svcClient->pipe = new NamedPipe(SVC_PIPE_PREFIX + pipeName, NamedPipeMode::NP_WRITE);
								
								//-- TODO: add neccessary config to this packet then send back to client
								
								//-- send response to client
								packet->serialize(buffer, &bufferLen);
								if (svcClient->pipe->write(buffer, bufferLen, 0) > 0){
									//-- add the client
									svcClients[pipeID] = svcClient;
								}
								else{
									delete svcClient;
								}
							}
							catch(string& e){
								//-- cannot connect to this pipe
								cout<<e<<endl;
							}
						}
					}
					break;
				}

			case SVC_CMD_SHUTDOWN_SVC:
				{
					uint64_t endpointID = packet->getEndpointID();
					SVCClient* svcClient = svcClients[endpointID];
					delete svcClient;
					svcClients[endpointID] = NULL;
					cout<<"removing svcClient: "<<endpointID<<endl;
					break;
				}

			case SVC_CMD_CREATE_ENDPOINT:
				{
					uint8_t buffer[SVC_DEFAULT_BUFSIZ];
					uint16_t bufferLen;

					uint64_t endpointID = packet->getEndpointID();
					SVCClient* svcClient = svcClients[endpointID];
					if (svcClient != NULL){
						uint8_t option;
						uint64_t pipeID;
						uint8_t hostAddress[1024];
						memset(hostAddress, 0, 1024);
						HostAddr* hostAddr;

						if (packet->popDataChunk(&option) && packet->popDataChunk(&pipeID) && packet->popDataChunk(&hostAddress)){
							uint8_t result;
							try{
								DaemonEndpoint* daemonEndpoint = daemonEndpointsByPipeID[pipeID];
								//-- remove dupplicated shutdowned endpoint to avoid mem leak
								if (daemonEndpoint != NULL){
									if (daemonEndpoint->working){
										//-- overriding working DaemonEndpoint
										throw ERR_CONFLIT_ADDRESS;
									}
									else{
										delete daemonEndpoint;
									}
								}
								string hostAddrStr = string((char*)hostAddress);
								//-- how to process this host address depends on which network used
								switch (daemonConfig->networkType){
									case NETWORK_TYPE_IPv4:
										{
											hostAddrStr = hostAddrStr + ":" +  to_string(daemonConfig->daemonPort);
										}
										break;
									default:
										break;
								}
								hostAddr = new HostAddr(daemonConfig->networkType, hostAddrStr);
								daemonEndpoint = new DaemonEndpoint(svcClient, option, pipeID, hostAddr);
								daemonEndpointsByPipeID[pipeID] = daemonEndpoint;
								result = SVC_SUCCESS;
							}
							catch(string& e){
								result = SVC_FAILED;
							}
							//-- send back result to client
							packet->pushDataChunk(&result, 1);
							packet->serialize(buffer, &bufferLen);
							svcClient->pipe->write(buffer, bufferLen, 0);
						}
						else{
							//-- request not valid, ignore
							cout<<"SVC_CMD_CREATE_ENDPOINT request not valid"<<endl;
						}

					}
					else{
						//-- request sent from unknown svc client, ignore
						cout<<"SVC_CMD_CREATE_ENDPOINT unknown client"<<endl;
					}
					break;
				}
					
			default:
				{
					break;
				}
		}
		delete packet;
	}
	else{
		//-- ingore data packet to daemon
		delete packet;
	}
}

void daemon_net_packet_handler(SVCPacket* packet, void* args){
	uint8_t infoByte = packet->getInfoByte();
	uint64_t sessionID = packet->getEndpointID();
	if ((infoByte & SVC_COMMAND_FRAME) != 0x00){
		enum SVCCommand cmd = (enum SVCCommand)packet->getExtraInfoByte();
		switch (cmd){
			case SVC_CMD_CONNECT_OUTER1:
				{
					printf("SVC_CMD_CONNECT_OUTER1 received\n");
					uint32_t appID;
					packet->popDataChunk(&appID);
					//-- check if client exists
					for (auto it = svcClients.begin(); it != svcClients.end(); it++){
						SVCClient* client = (SVCClient*)it->second;
						if (client->appID == appID){
							daemonEndpointsByPipeID[client->pipeID]->netReadingQueue->enqueue(packet);
							break;
						}
						delete packet;
					}
					break;
				}

			case SVC_CMD_CONNECT_OUTER2:
				{
					uint64_t sessionID = packet->getEndpointID();
					//-- find the matched DaemonEndpoint
					DaemonEndpoint* endpoint = NULL;
					for (auto it = daemonEndpointsByPipeID.begin(); it != daemonEndpointsByPipeID.end(); it++){
						endpoint = (DaemonEndpoint*)it->second;
						if (memcmp(&endpoint->sessionID, &sessionID, 4) == 0){
							break;
						}
					}
					if (endpoint != NULL){
						endpoint->netReadingQueue->enqueue(packet);
					}
					else{
						delete packet;
					}
					break;
				}

			default:
				{
					DaemonEndpoint* endpoint = daemonEndpointsBySessionID[sessionID];
					if (endpoint != NULL){
						endpoint->netReadingQueue->enqueue(packet);
					}
					else{
						delete packet;
					}
					break;
				}
		}
	}
	else{
		DaemonEndpoint* endpoint = daemonEndpointsBySessionID[sessionID];
		if (endpoint != NULL){
			endpoint->netReadingQueue->enqueue(packet);
		}
		else{
			delete packet;
		}
	}
}

//================================= GLOBAL FUNCTIONS' DEFINITION =====

void waitStop(){
	unique_lock<mutex> ul(stopMutex);
	//-- suspend and wait for working to be FALSE
	stopCV.wait(ul, []{return !working;});
	stopMutex.unlock();
}

int exitWithError(string err){
	cout<<err<<" (errno: "<<errno<<")"<<endl;
	return -1;
}

int showHelp(){
	cout<<"\nsvc-daemon: daemon process for svc-based applications";
	cout<<"\nusage:";
	
	cout<<"\n\t "<<ARG_DEFAULT_CONFIG<<" "<<ARG_CONFIG_PATH;
	cout<<"\n\t\t Generate svc-daemon's default configuration and save it to a file located at \""<<ARG_CONFIG_PATH<<"\".";
	cout<<"\n\t\t If \""<<ARG_CONFIG_PATH<<"\" is omitted then default to \"./"<<svcDefaultConfigFilename<<"\".\n";

	cout<<"\n\t "<<ARG_HELP;
	cout<<"\n\t\t Show this help content.\n";
	
	cout<<"\n\t "<<ARG_START<<" "<<ARG_CONFIG<<" "<<ARG_CONFIG_PATH;
	cout<<"\n\t\t Start a new instance of svc-daemon using the configuration inside \""<<ARG_CONFIG_PATH<<"\".";
	cout<<"\n\t\t If \""<<ARG_CONFIG<<" "<<ARG_CONFIG_PATH<<"\" is omitted then this command is equivalent as running";
	cout<<"\n\t\t\t "<<ARG_DEFAULT_CONFIG;
	cout<<"\n\t\t and then";
	cout<<"\n\t\t\t "<<ARG_START<<" "<<ARG_CONFIG<<" ./"<<svcDefaultConfigFilename<<"\n";

	cout<<"\n\t "<<ARG_START<<" "<<ARG_IMAGE<<" "<<ARG_IMAGE_PATH;
	cout<<"\n\t\t Start the svc-daemon using the previously saved information in \""<<ARG_IMAGE_PATH<<"\".\n";
	
	cout<<"\n\t "<<ARG_SHUTDOWN<<" ["<<ARG_IMAGE<<" "<<ARG_IMAGE_PATH<<"]";
	cout<<"\n\t\t Gracefully stop the running svc-daemon instance and (optionally) save";
	cout<<"\n\t\t all current endpoints' states to a file located at \""<<ARG_IMAGE_PATH<<"\".";
	cout<<"\n\t\t Using this command in combination with \""<<ARG_START<<" "<<ARG_IMAGE<<"\" for svc update/maintenance.\n";
	cout<<"\n";
	fflush(stdout);
	return 0;
}

int startDaemon(SVCDaemonImage* image){
	try{
		//-- copy config
		daemonConfig = image->config->clone();
		
		//-- TODO: all socket file instances are created in this temp folder.
		//-- If daemon failed to bind, due to a previous crash, just run: rm <path>/svc*
		//-- to clear all temp files.
		cout<<"temp dir: "<<utils::getOSTempDirectory(true)<<endl;

		//-- create a pipe to receive local data
		daemonLocalPipe = new NamedPipe(SVC_PIPE_PREFIX + SVC_DEFAULT_DAEMON_NAME, NamedPipeMode::NP_READ);
		localIncomingQueue = new MutexedQueue<SVCPacket*>();
		localPacketReader = new SVCPacketReader(daemonLocalPipe, localIncomingQueue, 0);
		localPacketHandler = new SVCPacketHandler(localIncomingQueue, daemon_local_packet_handler, NULL);

		//-- bind htp to localhost
		htpSocket = new HTPSocket(daemonConfig->networkType, 0);
		if (htpSocket->bind(new HostAddr(daemonConfig->networkType, daemonConfig->localHost)) != 0){
			daemonLocalPipe->close();
			localIncomingQueue->close();
			localPacketReader->stopWorking();
			localPacketHandler->stopWorking();
			delete localPacketHandler;
			delete localPacketReader;
			delete localIncomingQueue;
			delete daemonLocalPipe;
			return exitWithError(ERR_BINDING_SOCKET);
		}
		netIncomingQueue = new MutexedQueue<SVCPacket*>();
		netPacketReader = new SVCPacketReader(htpSocket, netIncomingQueue, SVCPacketReader::WITH_SENDER_ADDR);
		netPacketHandler = new SVCPacketHandler(netIncomingQueue, daemon_net_packet_handler, NULL);
		
		working = true;
		cout<<"SVC daemon is running..."<<endl;

		waitStop();
		shutdown();
		delete image;
		return 0;
	}
	catch (std::string& e){
		return exitWithError(e);
	}
}

int shutdownDaemon(bool saveImage, const string& imagePath){
	
	//-- try to connect to the running daemon
	try{
		daemonLocalPipe = new NamedPipe(SVC_PIPE_PREFIX + SVC_DEFAULT_DAEMON_NAME, NamedPipeMode::NP_WRITE);
	}
	catch (string& e){
		cout<<ERR_NOT_RUNNING<<endl;
		return -1;
	}

	//-- send a specific command to current daemon instance
	SVCPacket* packet = new SVCPacket();
	packet->setCommand(SVC_CMD_STOP_DAEMON);
	if (saveImage) {
		packet->pushDataChunk((uint8_t*)imagePath.c_str(), imagePath.size());
	}
	uint8_t save = saveImage? 0x01 : 0x00;
	packet->pushDataChunk(&save, 1);

	uint8_t buffer[SVC_DEFAULT_BUFSIZ];
	uint16_t packetLen;
	packet->serialize(buffer, &packetLen);
	daemonLocalPipe->write(buffer, packetLen, 0);

	delete packet;
	delete daemonLocalPipe;
	return 0;
}

int saveDefaultConfig(const string& configPath){
	ofstream configFile;
	configFile.open(configPath);
	if (configFile.is_open()){
		//-- TODO: serialize and writing config to configPath
		configFile.close();
		return 0;
	}
	else{
		return -1;
	}
}

bool loadConfig(const string& filename, SVCDaemonConfig* config){
	//-- TODO: this is for testing purpose. need implementing real file reading and parsing.
	config->networkType = svcDefaultConfig->networkType;
	config->localHost = svcDefaultConfig->localHost;
	config->daemonPort = svcDefaultConfig->daemonPort;
	return true;
}

bool loadImage(const string& filename, SVCDaemonImage** image){
	//-- TODO: need implementing file reading and parsing
	*image = new SVCDaemonImage();
	//-- 
	return true;
}

void shutdown(){
	//-- close daemonLocalPipe so localPacketReader will not block
	daemonLocalPipe->close();
	localPacketReader->stopWorking();
	//-- close localIncomingQueue so localPacketHandler will not block
	localIncomingQueue->close();
	localPacketHandler->stopWorking();

	//-- close dhtpSocket so netPacketReader will not block
	htpSocket->close();
	netPacketReader->stopWorking();
	//-- close netIncomingQueue so netPacketHandler will not block
	netIncomingQueue->close();
	netPacketHandler->stopWorking();

	delete daemonLocalPipe;
	delete localPacketReader;
	delete localIncomingQueue;
	delete localPacketHandler;

	delete htpSocket;
	delete netPacketReader;
	delete netIncomingQueue;
	delete netPacketHandler;

	for (auto it = svcClients.begin(); it != svcClients.end(); it++){
		if (it->second != NULL){
			cout<<"removing svcClient: "<<((SVCClient*)it->second)->pipeID<<endl;
		}
		delete it->second;
	}

	for (auto it = daemonEndpointsByPipeID.begin(); it != daemonEndpointsByPipeID.end(); it++){
		if (it->second != NULL){
			cout<<"removing endpoint: "<<((DaemonEndpoint*)it->second)->pipeID<<endl;
		}
		delete it->second;
	}

	cout<<"SVC daemon stopped."<<endl;
}