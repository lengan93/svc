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
struct SVCDaemonConfig{
	public:
		uint8_t networkType;
		string localHost;
		int daemonPort;		//-- specific in INET network
};

class SVCDaemonImage{
	public:
		struct SVCDaemonConfig config;
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
const string ARG_SHUTDOWN = "--shutdown";
const string ARG_CONFIG = "-c";
const string ARG_IMAGE = "-i";
const string ARG_CONFIG_PATH = "config_file_path";
const string ARG_IMAGE_PATH = "image_file_path";

const string svcDefaultConfigFilename = "svcdaemon.conf";

static SVCDaemonConfig svcDefaultConfig = {
	NETWORK_TYPE_IPv4, 	//-- networkType
	"0.0.0.0:9293",		//-- localHost
	9293				//-- daemonPort
};

//================================= GLOBAL VARIABLE ================
NamedPipe* daemonLocalPipe;
HTPSocket* htpSocket;

MutexedQueue<SVCPacket*>* localIncomingQueue;
SVCPacketReader* localPacketReader;
SVCPacketHandler* localPacketHandler;

MutexedQueue<SVCPacket*>* netIncomingQueue;
SVCPacketReader* netPacketReader;
SVCPacketHandler* netPacketHandler;

struct SVCDaemonConfig daemonConfig;

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
bool loadConfig(const string& filename, struct SVCDaemonConfig* config);
bool loadImage(const string& filename, SVCDaemonImage** image);
void shutdown();

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
							//-- send SVC_CMD_SHUTDOWN_ENDPOINT to other end
							cout<<"received SVC_CMD_SHUTDOWN_ENDPOINT"<<endl;
							_this->shutdown();
							break;
						}

					case SVC_CMD_CONNECT_INNER1:
						{
							cout<<"received SVC_CMD_CONNECT_INNER1"<<endl;
							uint8_t param[SVC_DEFAULT_BUFSIZ];
							uint16_t paramLen;

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
							uint32_t appID = svcClients[_this->pipeID]->appID;
							packet->pushDataChunk(&appID, APPID_LENGTH);

							//-- send the packet to internet
							packet->serialize(param, &paramLen);
							htpSocket->writeTo(_this->hostAddr, param, paramLen, 0);
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

							packet->serialize(param, &paramLen);
							htpSocket->writeTo(_this->hostAddr, param, paramLen, 0);
						}
						break;

					default:
						{
							break;
						}
				}
			}
			else{

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

			}
		}

		DaemonEndpoint(SVCClient* svcClient, uint8_t option, uint64_t pipeID, HostAddr* hostAddr){
			this->svcClient = svcClient;
			this->option = option;
			this->pipeID = pipeID;
			this->hostAddr = hostAddr;
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
				cout<<"endpoint: "<<this->pipeID<<" shutdown"<<endl;
			}
		}

		~DaemonEndpoint(){
			this->shutdown();
		}
};

//================================= MAIN =============================
int main(int argc, char* argv[]){

	//-- parse arguments
	if (argc == 1){
		return showHelp();
	}
	else{
		for (int i=1; i<argc; i++){
			if (argv[i] == ARG_HELP){
				return showHelp();
			}
			else if (argv[i] == ARG_START){
				if (i+2 < argc){
					SVCDaemonImage* image;
					if (argv[i+1] == ARG_CONFIG){
						image = new SVCDaemonImage();
						if (loadConfig(string(argv[i+2]), &(image->config))){
							return startDaemon(image);
						}
						else{
							return exitWithError(ERR_NOCONFIG);
						}
					}
					else if (argv[i+1] == ARG_IMAGE){
						if (loadImage(string(argv[i+2]), &image)){
							return startDaemon(image);
						}
						else{
							return exitWithError(ERR_NOIMAGE);
						}
					}
					else {
						return exitWithError(ERR_PARAM);
					}
				}
				else if (i == argc-1){
					if (saveDefaultConfig(svcDefaultConfigFilename) == 0){
						SVCDaemonImage* image = new SVCDaemonImage();
						image->config = svcDefaultConfig;
						return startDaemon(image);
					}
					else{
						return exitWithError(ERR_PERM);
					}
				}
				else{
					return exitWithError(ERR_PARAM);
				}
			}
			else if (argv[i] == ARG_SHUTDOWN){
				if (i+2 < argc){
					if (argv[i+1] == ARG_IMAGE){
						return shutdownDaemon(true, argv[i+2]);
					}
					else{
						return exitWithError(ERR_PARAM);
					}
				}
				else if (i == argc-1){
					return shutdownDaemon(false, "");
				}
				else{
					return exitWithError(ERR_PARAM);
				}
			}
			else if (argv[i] == ARG_DEFAULT_CONFIG){
				if (i+1 < argc){
					return saveDefaultConfig(argv[i+1]);
				}
				else{
					return saveDefaultConfig(svcDefaultConfigFilename);
				}
			}
			else{
				return exitWithError(ERR_PARAM);
			}
		}
	}
}

//================================= DAEMMON FUNCTIONS' DEFINITION ====
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
							// cout<<"appID: "<<appID<<endl;
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
					// cout<<"removing svcClient: "<<endpointID<<endl;
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
								switch (daemonConfig.networkType){
									case NETWORK_TYPE_IPv4:
										{
											hostAddrStr = hostAddrStr + ":" +  to_string(daemonConfig.daemonPort);
										}
										break;
									default:
										break;
								}
								hostAddr = new HostAddr(daemonConfig.networkType, hostAddrStr);
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
						}

					}
					else{
						//-- request sent from unknown svc client, ignore
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
					else
					{
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
		memcpy(&daemonConfig, &image->config, sizeof(SVCDaemonConfig));
		
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
		htpSocket = new HTPSocket(daemonConfig.networkType, 0);
		htpSocket->bind(new HostAddr(daemonConfig.networkType, daemonConfig.localHost));
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

bool loadConfig(const string& filename, struct SVCDaemonConfig* config){
	//-- TODO: this is for testing purpose. need implementing file reading and parsing.
	memcpy(config, &svcDefaultConfig, sizeof(struct SVCDaemonConfig));
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

/*
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
PacketHandler* daemonInetIncomingPacketHandler;
PeriodicWorker* endpointChecker;
uint16_t daemonEndpointCounter = 0;
volatile bool working;

//-- queues
MutexedQueue<SVCPacket*> daemonUnixIncomingQueue;
MutexedQueue<SVCPacket*> daemonInetIncomingQueue;

//-- reading loops and threads
pthread_t daemonUnixReadingThread;
pthread_t daemonInetReadingThread;
extern void* daemon_unix_reading_loop(void* args);
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
		static void* daemon_endpoint_inet_writing_loop(void* args);
		
		MutexedQueue<SVCPacket*> unixIncomingQueue;
		MutexedQueue<SVCPacket*> unixOutgoingQueue;
		MutexedQueue<SVCPacket*> unixToBeSentQueue;
		MutexedQueue<SVCPacket*> inetIncomingQueue;
		MutexedQueue<SVCPacket*> inetOutgoingQueue;
		MutexedQueue<SVCPacket*> inetToBeSentQueue;
		
		PacketHandler* unixIncomingPacketHandler;
		PacketHandler* unixOutgoingPacketHandler;
		PacketHandler* inetOutgoingPacketHandler;
		PacketHandler* inetIncomingPacketHandler;
				
		pthread_t unixReadingThread;
		pthread_t unixWritingThread;
		pthread_t inetWritingThread;
		
		//-- private members
		volatile bool shutdownCalled;
		volatile bool svcShutdownCall;
		volatile bool daemonShutdownCall;
		volatile bool working;
		
		bool isAuth;
		bool isInitiator;
		
		bool beatUp;
		int initLiveTime;
		int beatLiveTime;
		
		int dmnSocket;
		struct sockaddr_in remoteAddr;
		size_t remoteAddrLen;	

		//-- crypto protocol variables
		pthread_mutex_t stateMutex;
		SVCCommand state;
		SVCPacket* encryptedECPoint;
		SVCPacket* encryptedProof;
		ECCurve* curve;	
		ECPoint* gxy;
		SHA256 sha256;
		AESGCM* aesgcm;
		uint64_t endpointID;
		uint64_t sendSequence;
		uint64_t recvSequence;
		mpz_t randomX;
		
		//-- constructors/destructors
		DaemonEndpoint(uint64_t endpointID);
		~DaemonEndpoint();
				
		//-- public methods
		bool checkInitLiveTime(int interval);
		bool isAuthenticated();
		
		void encryptPacket(SVCPacket* packet);
		bool decryptPacket(SVCPacket* packet);
		
		int connectToAppSocket();
		int startInetHandlingRoutine();		
		void connectToAddress(uint32_t remoteAddress);
		void connectToAddress(const struct sockaddr_in* sockAddr, socklen_t sockLen);
		
		void shutdownEndpoint();
};

DaemonEndpoint::DaemonEndpoint(uint64_t endpointID){
	
	const char* error;
	this->endpointID = endpointID;	
	
	this->unixReadingThread = 0;
	this->unixWritingThread = 0;
	this->inetWritingThread = 0;
	
	this->working = true;
	
	this->unixIncomingPacketHandler = NULL;
	this->unixOutgoingPacketHandler = NULL;
	this->inetIncomingPacketHandler = NULL;
	this->inetOutgoingPacketHandler = NULL;
	
	pthread_mutexattr_t mutexAttr;
	pthread_mutexattr_init(&mutexAttr);
	pthread_mutex_init(&this->stateMutex, &mutexAttr);
	this->state = SVC_CMD_CREATE_ENDPOINT;		
	
	//-- create dmn unix socket, bind 
	this->dmnSocket = socket(AF_LOCAL, SOCK_DGRAM, 0);
	struct sockaddr_un dmnSockAddr;
	string dmnSockPath = string(SVC_ENDPOINT_DMN_PATH_PREFIX) + hexToString((uint8_t*)&endpointID, ENDPOINTID_LENGTH);
	memset(&dmnSockAddr, 0, sizeof(dmnSockAddr));
	dmnSockAddr.sun_family = AF_LOCAL;
	dmnSockAddr.sun_path[0] = '\0';
	memcpy(dmnSockAddr.sun_path+1, dmnSockPath.c_str(), dmnSockPath.size());
	
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
		try{
			this->unixIncomingPacketHandler = new PacketHandler(&this->unixIncomingQueue, daemon_endpoint_unix_incoming_packet_handler, this);		
			this->unixOutgoingPacketHandler = new PacketHandler(&this->unixOutgoingQueue, daemon_endpoint_unix_outgoing_packet_handler, this);
			goto endpoint_success;
		}
		catch(...){
			this->working = false;
			pthread_join(this->unixReadingThread, NULL);
			error = SVC_ERROR_CRITICAL;
			goto endpoint_error;
		}
	}
	
	endpoint_error:		
		throw error;
		
	endpoint_success:
		mpz_init(this->randomX);
		this->aesgcm = NULL;
		this->curve = NULL;
		this->encryptedECPoint = NULL;
		this->encryptedProof = NULL;
		
		this->beatUp = true;		
		this->initLiveTime = SVC_ENDPOINT_INIT_LIVETIME;
		this->beatLiveTime = SVC_ENDPOINT_BEAT_LIVETIME;
		this->sendSequence = 0;
		this->recvSequence = 0;
		this->isAuth = false;
		this->isInitiator = false;
		this->shutdownCalled = false;
		this->svcShutdownCall = false;
		this->daemonShutdownCall = false;
		this->remoteAddrLen = sizeof(this->remoteAddr);
		memset(&this->remoteAddr, 0, this->remoteAddrLen);
}

void DaemonEndpoint::shutdownEndpoint(){
	if (!this->shutdownCalled){
		this->shutdownCalled = true;		
		
		int joinrs;
	
		if (this->isAuth & !this->daemonShutdownCall){			
			SVCPacket* packet = new SVCPacket(this->endpointID);
			packet->setCommand(SVC_CMD_SHUTDOWN_ENDPOINT);
			packet->packet[INFO_BYTE] |= SVC_ENCRYPTED;
			this->inetOutgoingQueue.enqueue(packet);
		}
		
		if (!this->svcShutdownCall){
			SVCPacket* packet = new SVCPacket(this->endpointID);
			packet->setCommand(SVC_CMD_SHUTDOWN_ENDPOINT);
			this->unixOutgoingQueue.enqueue(packet);
		}
		
		this->working = false;
	
		shutdown(this->dmnSocket, SHUT_RD); //-- this will make recv return
		//-- stop reading packets
		if (this->unixReadingThread!=0){
			joinrs = pthread_join(this->unixReadingThread, NULL);		
		}
	
		//-- process residual incoming packets
		if (this->unixIncomingPacketHandler!=NULL){
			this->unixIncomingPacketHandler->stopWorking();
			joinrs = this->unixIncomingPacketHandler->waitStop();		
			delete this->unixIncomingPacketHandler;
		}
	
		if (this->inetIncomingPacketHandler!=NULL){
			this->inetIncomingPacketHandler->stopWorking();
			joinrs = this->inetIncomingPacketHandler->waitStop();		
			delete this->inetIncomingPacketHandler;
		}
	
		//-- process residual outgoing packets
		if (this->unixOutgoingPacketHandler!=NULL){
			this->unixOutgoingPacketHandler->stopWorking();
			joinrs = this->unixOutgoingPacketHandler->waitStop();		
			delete this->unixOutgoingPacketHandler;
		}
	
		if (this->inetOutgoingPacketHandler!=NULL){
			this->inetOutgoingPacketHandler->stopWorking();
			joinrs = this->inetOutgoingPacketHandler->waitStop();
			delete this->inetOutgoingPacketHandler;
		}			

		shutdown(this->dmnSocket, SHUT_WR);
		//-- stop sending packets
		if (this->unixWritingThread!=0){
			joinrs = pthread_join(this->unixWritingThread, NULL);		
		}
	
		if (this->inetWritingThread!=0){
			joinrs = pthread_join(this->inetWritingThread, NULL);
		}
			
		//-- remove instances
		close(this->dmnSocket);
		mpz_clear(this->randomX);
		if (this->encryptedProof!=NULL) delete this->encryptedProof;
		if (this->encryptedECPoint!=NULL) delete this->encryptedECPoint;
		delete this->aesgcm;
		delete this->curve;
		this->aesgcm = NULL;
		this->curve = NULL;
		cout<<"\nendpoint shutdown: "); printBuffer((uint8_t*)&this->endpointID, ENDPOINTID_LENGTH); fflush(stdout);
	}
}

DaemonEndpoint::~DaemonEndpoint(){	
	shutdownEndpoint();
}

int DaemonEndpoint::connectToAppSocket(){
	//-- then connect to app socket
	int rs;
	struct sockaddr_un appSockAddr;
	string appSockPath = string(SVC_ENDPOINT_APP_PATH_PREFIX) + hexToString((uint8_t*)&endpointID, ENDPOINTID_LENGTH);
	memset(&appSockAddr, 0, sizeof(appSockAddr));
	appSockAddr.sun_family = AF_LOCAL;
	appSockAddr.sun_path[0]='\0';
	memcpy(appSockAddr.sun_path+1, appSockPath.c_str(), appSockPath.size());
	if (connect(this->dmnSocket, (struct sockaddr*) &appSockAddr, sizeof(appSockAddr)) == 0){
		//-- start daemon endpoint unix writing		
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		if (pthread_create(&this->unixWritingThread, &attr, daemon_endpoint_unix_writing_loop, this) == 0 ){			
			rs = 0;
		}
		else{
			rs = -1;
		}
		pthread_attr_destroy(&attr);
	}
	else{		
		rs = -1;
	}
	return rs;
}

int DaemonEndpoint::startInetHandlingRoutine(){
	int rs;
	//-- create packethandler for inet outgoing packet and writing thread
	this->inetOutgoingPacketHandler = new PacketHandler(&this->inetOutgoingQueue, daemon_endpoint_inet_outgoing_packet_handler, this);	
	this->inetIncomingPacketHandler = new PacketHandler(&this->inetIncomingQueue, daemon_endpoint_inet_incoming_packet_handler, this);
	
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	if (pthread_create(&this->inetWritingThread, &attr, daemon_endpoint_inet_writing_loop, this) == 0){
		rs = 0;
	}
	else{
		rs = -1;
	}
	return rs;
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

void DaemonEndpoint::daemon_endpoint_unix_outgoing_packet_handler(SVCPacket* packet, void* args){
	DaemonEndpoint* _this = (DaemonEndpoint*)args;
	_this->unixToBeSentQueue.enqueue(packet);
}

void DaemonEndpoint::daemon_endpoint_inet_outgoing_packet_handler(SVCPacket* packet, void* args){
	DaemonEndpoint* _this = (DaemonEndpoint*)args;
	uint8_t infoByte = packet->packet[INFO_BYTE];
	if ((infoByte & SVC_ENCRYPTED)!=0x00){
		if (_this->aesgcm!=NULL){
			//-- encrypt packet before send out
			_this->sendSequence++;
			packet->setSequence(_this->sendSequence);
			_this->encryptPacket(packet);			
			_this->inetToBeSentQueue.enqueue(packet);
		}
		else{
			//-- secure connection not yet established, silently discard
			delete packet;
		}
	}
	else{
		_this->sendSequence++;
		packet->setSequence(_this->sendSequence);
		_this->inetToBeSentQueue.enqueue(packet);
	}
}

void* DaemonEndpoint::daemon_endpoint_inet_writing_loop(void* args){
	DaemonEndpoint* _this = (DaemonEndpoint*)args;
	SVCPacket* packet;
	int sendrs;
	while (_this->working || _this->inetOutgoingQueue.notEmpty() || _this->inetToBeSentQueue.notEmpty()){
		packet = _this->inetToBeSentQueue.dequeueWait(1000);
		if (packet!=NULL){
			sendrs = sendto(daemonInSocket, packet->packet, packet->dataLen, 0, (struct sockaddr*)&_this->remoteAddr, _this->remoteAddrLen);			
			//cout<<"\ndaemon inet writes packet %d: errno: %d", sendrs, errno); printBuffer(packet->packet, packet->dataLen); fflush(stdout);
			delete packet;
			//cout<<"-"); fflush(stdout);
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


void DaemonEndpoint::encryptPacket(SVCPacket* packet){

	uint8_t* iv = packet->packet+ENDPOINTID_LENGTH+1;
	uint16_t ivLen = SEQUENCE_LENGTH;	
	
	uint8_t* tag;
	uint16_t tagLen;	
	uint8_t* encrypted;
	uint32_t encryptedLen;

	//-- set infoByte
	packet->packet[INFO_BYTE] |= SVC_ENCRYPTED;
	
	//cout<<"\nencrypt packet with:");
	//cout<<"\niv: "); printBuffer(iv, ivLen); fflush(stdout);
	//cout<<"\naad: "); printBuffer(packet->packet, SVC_PACKET_HEADER_LEN); fflush(stdout);
	//cout<<"\ndata: "); printBuffer(packet->packet+SVC_PACKET_HEADER_LEN, packet->dataLen); fflush(stdout);
	
	
	this->aesgcm->encrypt(iv, ivLen, packet->packet+SVC_PACKET_HEADER_LEN, packet->dataLen - SVC_PACKET_HEADER_LEN, packet->packet, SVC_PACKET_HEADER_LEN, &encrypted, &encryptedLen, &tag, &tagLen);
	
	//cout<<"\ngot:");
	//cout<<"\nencrypted: "); printBuffer(encrypted, encryptedLen); fflush(stdout);
	//cout<<"\ntag: "); printBuffer(tag, tagLen); fflush(stdout);
	
	
	//-- set body to be encrypted
	packet->setBody(encrypted, encryptedLen);
	//-- copy tag and tagLen to the end of packet
	packet->pushDataChunk(tag, tagLen);	
	
	free(encrypted);
	free(tag);
}

bool DaemonEndpoint::decryptPacket(SVCPacket* packet){
	bool rs;
	uint8_t* iv = (uint8_t*)(packet->packet + ENDPOINTID_LENGTH + 1);
	uint16_t ivLen = SEQUENCE_LENGTH;
	uint8_t* aad = packet->packet;
	uint16_t aadLen = SVC_PACKET_HEADER_LEN;	
	
	uint16_t tagLen = *((uint16_t*)(packet->packet+packet->dataLen - 2));
	uint8_t* tag = packet->packet+packet->dataLen-2-tagLen;
	
	uint8_t* decrypted;
	uint32_t decryptedLen;
	
		
	//cout<<"\ndecrypt packet with:");
	//cout<<"\niv: "); printBuffer(iv, ivLen); fflush(stdout);
	//cout<<"\naad: "); printBuffer(aad, aadLen); fflush(stdout);
	//cout<<"\ntag: "); printBuffer(tag, tagLen); fflush(stdout);
	//cout<<"\nencrypted: "); printBuffer(packet->packet+SVC_PACKET_HEADER_LEN, packet->dataLen); fflush(stdout);
	
	rs = this->aesgcm->decrypt(iv, ivLen, packet->packet+SVC_PACKET_HEADER_LEN, packet->dataLen - SVC_PACKET_HEADER_LEN - 2 - tagLen, aad, aadLen, tag, tagLen, &decrypted, &decryptedLen);
	
	//cout<<"\ngot:");
	//cout<<"\ndecrypted: "); printBuffer(decrypted, decryptedLen); fflush(stdout);
		
	//-- set body to be decrypted
	if (rs){
		packet->setBody(decrypted, decryptedLen);
		packet->packet[INFO_BYTE] &= ~SVC_ENCRYPTED;
	}
	free(decrypted);
	return rs;
}

void* DaemonEndpoint::daemon_endpoint_unix_reading_loop(void* args){
	DaemonEndpoint* _this = (DaemonEndpoint*)args;
	
	int readrs;
	uint8_t buffer[SVC_DEFAULT_BUFSIZ] = "";
	while (_this->working){
		readrs = recv(_this->dmnSocket, buffer, SVC_DEFAULT_BUFSIZ, 0);				
		if (readrs>0){	
			_this->unixIncomingQueue.enqueue(new SVCPacket(buffer, readrs));
			//cout<<"\ndaemon endpoint unix reads packet:"); printBuffer(buffer, readrs); fflush(stdout);
		}
		else{
			//cout<<"\ndaemon endpoint unix reads fail, errno: %d", errno);
		}
	}
	pthread_exit(EXIT_SUCCESS);
}

void* DaemonEndpoint::daemon_endpoint_unix_writing_loop(void* args){
	DaemonEndpoint* _this = (DaemonEndpoint*)args;
	SVCPacket* packet;
	int sendrs;
	while (_this->working || _this->unixOutgoingQueue.notEmpty() || _this->unixToBeSentQueue.notEmpty()){		
		packet = _this->unixToBeSentQueue.dequeueWait(1000);
		if (packet!=NULL){
			sendrs = send(_this->dmnSocket, packet->packet, packet->dataLen, 0);
			if (sendrs == -1){
				//cout<<"\ndaemon unix writes packet fail, errno: %d", errno); //111 or 107
			}
			delete packet;		
		}
	}
	pthread_exit(EXIT_SUCCESS);
}

void DaemonEndpoint::daemon_endpoint_inet_incoming_packet_handler(SVCPacket* packet, void* args){
	
	uint16_t paramLen;
	uint8_t param[SVC_DEFAULT_BUFSIZ];	
	
	DaemonEndpoint* _this = (DaemonEndpoint*)args;
	uint8_t infoByte = packet->packet[INFO_BYTE];
	
	_this->recvSequence++;
	
	//-- check for encryption
	bool decryptSuccess = true;
	if (((infoByte & SVC_ENCRYPTED) != 0x00) && (_this->aesgcm!=NULL)){
		decryptSuccess = _this->decryptPacket(packet);
	}
	
	if (decryptSuccess){
		//cout<<"\ndaemon inet incoming: packet after decrypt: "); printBuffer(packet->packet, packet->dataLen); fflush(stdout);
		//-- check sequence and address to be update
		if (memcmp(&_this->remoteAddr, &packet->srcAddr, _this->remoteAddrLen)!=0){
			_this->connectToAddress((struct sockaddr_in*)&packet->srcAddr, packet->srcAddrLen);
		}
		
		if ((infoByte & SVC_COMMAND_FRAME) != 0x00){
			enum SVCCommand cmd = (enum SVCCommand)packet->packet[CMD_BYTE];
			switch (cmd){
				case SVC_CMD_SHUTDOWN_ENDPOINT:
					cout<<"\nother end of connection has shutdown"); fflush(stdout);
					delete packet;
					_this->daemonShutdownCall = true;
					_this->working = false;
					break;
					
				case SVC_CMD_CONNECT_OUTER2:
					pthread_mutex_lock(&_this->stateMutex);
					if (_this->state < SVC_CMD_CONNECT_OUTER2){		
						//-- pop encrypted proof					
						if (!packet->popDataChunk(param, &paramLen)){
							delete packet;
							pthread_mutex_unlock(&_this->stateMutex);
							break;
						}
						_this->encryptedProof = new SVCPacket(param, paramLen);
					
						if (!packet->popDataChunk(param, &paramLen)){
							delete _this->encryptedProof;
							delete packet;
							pthread_mutex_unlock(&_this->stateMutex);
							break;
						}
						_this->encryptedECPoint = new SVCPacket(param, paramLen);
		
						//-- change command to INNER_4				
						packet->setCommand(SVC_CMD_CONNECT_INNER4);
						//-- app svc is still waiting for the 'old' endpointID, push the current endpointID as new param
						packet->pushDataChunk(packet->packet+1, ENDPOINTID_LENGTH);
						//-- clear the 6&7 byte of endpointID
						packet->packet[1+6]=0x00;
						packet->packet[1+7]=0x00;				
						_this->unixOutgoingQueue.enqueue(packet);
						_this->state = SVC_CMD_CONNECT_OUTER2;
						pthread_mutex_unlock(&_this->stateMutex);
					}
					else{
						delete packet;
						pthread_mutex_unlock(&_this->stateMutex);
					}
					break;
			
				case SVC_CMD_CONNECT_OUTER3:
					pthread_mutex_lock(&_this->stateMutex);
					if (_this->state < SVC_CMD_CONNECT_OUTER3){					
						packet->setCommand(SVC_CMD_CONNECT_INNER8);
						_this->unixOutgoingQueue.enqueue(packet);
						_this->state = SVC_CMD_CONNECT_OUTER3;
						pthread_mutex_unlock(&_this->stateMutex);
					}
					else{
						delete packet;
						pthread_mutex_unlock(&_this->stateMutex);
					}
					break;
				
				default:
					delete packet;
					break;
			}
		}
		else{
			//-- forward to app
			_this->unixOutgoingQueue.enqueue(packet);
		}
	}
	else{
		//cout<<"\npacket decrypted failed. removed."); fflush(stdout);
		delete packet;
	}	
	
}

void DaemonEndpoint::daemon_endpoint_unix_incoming_packet_handler(SVCPacket* packet, void* args){
				
	AES256* aes256 = NULL;
	int requested_security_strength;
	mpz_t randomNumber;
		
	uint16_t ecpointHexLen;	
	
	uint8_t solutionProof[SVC_DEFAULT_BUFSIZ];
	uint16_t solutionProofLen;
	
	uint8_t solution[SVC_DEFAULT_BUFSIZ];
	uint16_t solutionLen;
	
	string hashValue;
	
	uint8_t param[SVC_DEFAULT_BUFSIZ];	
	uint16_t paramLen;
	
	uint8_t aeskey[KEY_LENGTH];
	char ecpointHexString[SVC_DEFAULT_BUFSIZ];

	uint8_t* iv;
	uint16_t ivLen;
	uint8_t* tag;
	uint16_t tagLen;
	uint8_t* aad;
	uint16_t aadLen;
	
	uint8_t* encrypted;
	uint32_t encryptedLen;
	uint8_t* decrypted;
	uint32_t decryptedLen;
	uint8_t* data;
	uint32_t dataLen;

	ECPoint* ecpoint;
	int sendrs;
	
	DaemonEndpoint* _this = (DaemonEndpoint*)args;
	uint8_t infoByte = packet->packet[INFO_BYTE];
			
	if ((infoByte & SVC_COMMAND_FRAME) != 0x00){
		
		enum SVCCommand cmd = (enum SVCCommand)packet->packet[CMD_BYTE];	
		uint64_t endpointID = *((uint64_t*)(packet->packet+1));
					
		switch (cmd){		
			case SVC_CMD_CHECK_ALIVE:
				//-- reset beatLiveTime
				_this->beatUp = true;
				_this->beatLiveTime = SVC_ENDPOINT_BEAT_LIVETIME;
				_this->inetOutgoingQueue.enqueue(packet);
				//delete packet;
				break;
				
			case SVC_CMD_SHUTDOWN_ENDPOINT:				
				if (_this->isAuth){
					//-- send terminating command					
					_this->svcShutdownCall = true;
				}
				delete packet;
				_this->working = false;
				break;
			
			case SVC_CMD_CONNECT_INNER1:
				pthread_mutex_lock(&_this->stateMutex);
				if (_this->state < SVC_CMD_CONNECT_INNER1){				
					//-- extract remote address
					if (!packet->popDataChunk(param, &paramLen)){															
						delete packet;
						pthread_mutex_unlock(&_this->stateMutex);
						break;
					}		
					_this->connectToAddress(*((uint32_t*)param));
					if (_this->startInetHandlingRoutine()!=0){
						delete packet;
						_this->working = false;
						pthread_mutex_unlock(&_this->stateMutex);
						break;
					}
					
					//-- extract challengeSecret x
					if (!packet->popDataChunk(param, &paramLen)){
						delete packet;
						pthread_mutex_unlock(&_this->stateMutex);
						break;
					}
					
					//-- use SHA256(x) as an AES256 key
					hashValue = _this->sha256.hash(string((char*)param, paramLen));
					stringToHex(hashValue, aeskey); //AES key is guaranteed to be 256 bits length
					if (aes256!=NULL) delete aes256;
					aes256 = new AES256(aeskey);
					
					//-- generate STS-gx
					if (_this->curve == NULL) _this->curve = new ECCurve();
					requested_security_strength = _this->curve->getRequestSecurityLength();					
					generateRandomNumber(&_this->randomX, requested_security_strength);
					ecpoint = new ECPoint();
					_this->curve->mul(ecpoint, _this->curve->g, &_this->randomX);
					paramLen = 0;
					//-- use created AES to encrypt gx = Ex(gx), copy to param
					mpz_get_str(ecpointHexString, 16, ecpoint->x);
					ecpointHexLen = strlen(ecpointHexString) + 1;			
					
					memcpy(param + paramLen, &ecpointHexLen, 2);
					paramLen += 2;
					memcpy(param + paramLen, ecpointHexString, ecpointHexLen);	
					paramLen += ecpointHexLen;					
				
					mpz_get_str(ecpointHexString, 16, ecpoint->y);
					ecpointHexLen = strlen(ecpointHexString)+1; 
					
					memcpy(param + paramLen, &ecpointHexLen, 2);
					paramLen += 2;				
					memcpy(param+paramLen, ecpointHexString, ecpointHexLen);
					paramLen += ecpointHexLen;					
				
					aes256->encrypt(param, paramLen, &encrypted, &encryptedLen);					
					packet->pushDataChunk(encrypted, encryptedLen);
					
					free(encrypted);
					delete aes256;
					delete ecpoint;
					
					//-- switch commandID
					packet->setCommand(SVC_CMD_CONNECT_OUTER1);
					//-- send the packet to internet					
					_this->inetOutgoingQueue.enqueue(packet);
					_this->state = SVC_CMD_CONNECT_INNER1;
					pthread_mutex_unlock(&_this->stateMutex);
				}
				else{
					delete packet;
					pthread_mutex_unlock(&_this->stateMutex);
				}				
				break;
			
			case SVC_CMD_CONNECT_INNER3:			
				pthread_mutex_lock(&_this->stateMutex);
				if (_this->state < SVC_CMD_CONNECT_INNER3){					
					//-- app responded with CONNECT_INNER3, now can connect to app socket
					_this->connectToAppSocket();
				
					if (!packet->popDataChunk(param, &paramLen)){
						delete packet;
						pthread_mutex_unlock(&_this->stateMutex);
						break;
					}
					//-- use SHA256(x) as an AES256 key
					hashValue = _this->sha256.hash(string((char*)param, paramLen));
					stringToHex(hashValue, aeskey); //-- aes key used to decrypt k1
				
					aes256 = new AES256(aeskey);				
					aes256->decrypt(_this->encryptedECPoint->packet, _this->encryptedECPoint->dataLen, &data, &dataLen);
				
					//-- construct gx from decrypted K1				
					paramLen = *((uint16_t*)data);
				
					//-- !! check if the decrypt ecpoint data is at least VALID, by verifying the null-terminator at the end of each number
					//-- otherwise the new ECPoint will be created with buffer-overflow error
					if ((data[1+paramLen] == 0x00) && (data[dataLen-1] == 0x00)){
						ecpoint = new ECPoint((char*)(data + 2) , (char*)(data + 4 + paramLen));				
						//-- extract challengeSecret y
						if (!packet->popDataChunk(param, &paramLen)){
							free(data);
							delete aes256;
							delete packet;
							delete ecpoint;
							pthread_mutex_unlock(&_this->stateMutex);
							break;
						}
						//-- use SHA256(y) as an AES256 key
						hashValue = _this->sha256.hash(string((char*)param, paramLen));
						//-- create new aes key to encrypt
						stringToHex(hashValue, aeskey);
						delete aes256;
						aes256 = new AES256(aeskey);
					
						//-- generate random number y
						if (_this->curve == NULL) _this->curve = new ECCurve();					
						requested_security_strength = _this->curve->getRequestSecurityLength();
						mpz_init(randomNumber);
						generateRandomNumber(&randomNumber,requested_security_strength);			
						//-- generate shared secret gxy			
						_this->gxy = new ECPoint();
						_this->curve->mul(_this->gxy, ecpoint, &randomNumber);					
									
						mpz_get_str(ecpointHexString, 16, _this->gxy->x);
						ecpointHexLen = strlen(ecpointHexString);
						memcpy(param, ecpointHexString, ecpointHexLen);
						paramLen = ecpointHexLen;					
				
						mpz_get_str(ecpointHexString, 16, _this->gxy->x);
						ecpointHexLen = strlen(ecpointHexString);
						memcpy(param + paramLen , ecpointHexString, ecpointHexLen);
						paramLen += ecpointHexLen;
					
						delete _this->gxy;
					
						if (_this->aesgcm == NULL){
							//-- aesgcm key = hash(gxy.x || gxy.y)
							hashValue = _this->sha256.hash(string((char*)param, paramLen));
							stringToHex(hashValue, aeskey);
							_this->aesgcm = new AESGCM(aeskey, (enum SecurityParameter)requested_security_strength);					
						}
					
						//-- pop solution proof to be encrypted
						if (!packet->popDataChunk(solutionProof, &solutionProofLen)){
							free(data);
							delete _this->aesgcm;
							_this->aesgcm = NULL;
							delete packet;
							delete aes256;
							delete ecpoint;	
							pthread_mutex_unlock(&_this->stateMutex);					
							break;
						}
				
						//-- gererate STS-gy
						_this->curve->mul(ecpoint, _this->curve->g, &randomNumber);
						mpz_clear(randomNumber);
						//-- use created AES to encrypt gy = Ey(gy), copy to param
						mpz_get_str(ecpointHexString, 16, ecpoint->x);
						ecpointHexLen = strlen(ecpointHexString) + 1;				
						paramLen = 0;
						memcpy(param + paramLen, &ecpointHexLen, 2);
						paramLen += 2;
						memcpy(param + paramLen, ecpointHexString, ecpointHexLen);
						paramLen += ecpointHexLen;
				
						mpz_get_str(ecpointHexString, 16, ecpoint->y);
						ecpointHexLen = strlen(ecpointHexString) + 1;
						memcpy(param + paramLen, &ecpointHexLen, 2);
						paramLen += 2;
						memcpy(param+paramLen, ecpointHexString, ecpointHexLen);
						paramLen += ecpointHexLen;
						delete ecpoint;	
					
						aes256->encrypt(param, paramLen, &encrypted, &encryptedLen);
					
						//-- switch command
						packet->setCommand(SVC_CMD_CONNECT_OUTER2);
						//-- attach Ey(gy) to packet
						packet->pushDataChunk(encrypted, encryptedLen);					
						free(encrypted);
				
						//-- encrypt solution proof then attach to packet
						//-- generate random iv, the first 2 byte are used to store ivLen				
						generateRandomData(requested_security_strength, param + 2);
				
						_this->aesgcm->encrypt(param + 2, requested_security_strength, solutionProof, solutionProofLen, NULL, 0, &encrypted, &encryptedLen, &tag, &tagLen);					
						//-- add iv, encrypted and tag to param				
						paramLen = 0;
						memcpy(param + paramLen, &requested_security_strength, 2);
						paramLen += 2 + requested_security_strength;
						//-- iv is already pre-generated
						memcpy(param + paramLen, &encryptedLen, 2);
						paramLen += 2;
						memcpy(param + paramLen, encrypted, encryptedLen);
						paramLen += encryptedLen;					
						memcpy(param + paramLen, &tagLen, 2);
						paramLen += 2;
						memcpy(param + paramLen, tag, tagLen);
						paramLen += tagLen;					
						packet->pushDataChunk(param, paramLen);
						free(encrypted);
						free(tag);
						delete aes256;
						_this->state = SVC_CMD_CONNECT_INNER3;
						pthread_mutex_unlock(&_this->stateMutex);
						//-- send this packet to internet
						_this->inetOutgoingQueue.enqueue(packet);
					}
					else{
						//-- decryted gx is damaged
						pthread_mutex_unlock(&_this->stateMutex);	
						delete packet;
					}
					free(data);
				}
				else{
					delete packet;
					pthread_mutex_unlock(&_this->stateMutex);
				}
				break;		
			
			case SVC_CMD_CONNECT_INNER5:
				pthread_mutex_lock(&_this->stateMutex);
				if (_this->state < SVC_CMD_CONNECT_INNER5){
					requested_security_strength = _this->curve->getRequestSecurityLength();		
					if (!packet->popDataChunk(solution, &solutionLen)){
						delete packet;
						pthread_mutex_unlock(&_this->stateMutex);
						break;
					}
			
					//-- hash this solution to create the aes256 key to decrypt encryptedECPoint from CONNECT_OUTER2
					hashValue = _this->sha256.hash(string((char*)solution, solutionLen));
					stringToHex(hashValue, aeskey); //-- aes key used to decrypt k1
					aes256 = new AES256(aeskey);
					aes256->decrypt(_this->encryptedECPoint->packet, _this->encryptedECPoint->dataLen, &data, &dataLen);
				
					delete aes256;
					//-- construct gy from decrypted k2
			
					paramLen = *((uint16_t*)data);				
					//-- !! check these gy_x and gy_y
					if ((data[1+paramLen] == 0x00) && (data[dataLen-1] == 0x00)){
						ecpoint = new ECPoint((char*)(data + 2) , (char*)(data + 4 + paramLen));
						free(data);
						//-- generate shared secret gxy
						_this->gxy = new ECPoint();
						_this->curve->mul(_this->gxy, ecpoint, &_this->randomX);					
						delete ecpoint;
				
						//-- generate aesgcm to decrypt solution proof
						mpz_get_str(ecpointHexString, 16, _this->gxy->x);
						ecpointHexLen = strlen(ecpointHexString);
						memcpy(param, ecpointHexString, ecpointHexLen);
						paramLen = ecpointHexLen;					
				
						mpz_get_str(ecpointHexString, 16, _this->gxy->x);
						ecpointHexLen = strlen(ecpointHexString);
						memcpy(param + paramLen , ecpointHexString, ecpointHexLen);
						paramLen += ecpointHexLen;	
					
						delete _this->gxy;			
				
						if (_this->aesgcm == NULL){
							//-- aesgcm key = hash(gxy.x || gxy.y)
							hashValue = _this->sha256.hash(string((char*)param, paramLen));
							stringToHex(hashValue, aeskey);						
							_this->aesgcm = new AESGCM(aeskey, (enum SecurityParameter)requested_security_strength);
						
							//-- decrypt the solution proof
							iv = _this->encryptedProof->packet+2;
							ivLen = *((uint16_t*)_this->encryptedProof->packet);						
							encrypted = _this->encryptedProof->packet + 4 + ivLen;
							encryptedLen = *((uint16_t*)(_this->encryptedProof->packet + 2 + ivLen));								
							tag = _this->encryptedProof->packet + 6 + ivLen + encryptedLen;
							tagLen = *((uint16_t*)(_this->encryptedProof->packet + 4 + ivLen + encryptedLen));						
							if (_this->aesgcm->decrypt(iv, ivLen, encrypted, encryptedLen, NULL, 0, tag, tagLen, &decrypted, &decryptedLen)){
								//-- solution proof decrypted succeeded by aesgcm							
								//-- forward CONNECT_INNER6 to app
								packet->setCommand(SVC_CMD_CONNECT_INNER6);
								packet->pushDataChunk(decrypted, decryptedLen);	
								_this->state = SVC_CMD_CONNECT_INNER5;											
								_this->unixOutgoingQueue.enqueue(packet);
								pthread_mutex_unlock(&_this->stateMutex);
							}
							else{							
								delete packet;
								pthread_mutex_unlock(&_this->stateMutex);
							}						
							free(decrypted);
						}
						else{
							delete packet;
							pthread_mutex_unlock(&_this->stateMutex);
						}		
					}
					else{		
						free(data);
						delete packet;
						pthread_mutex_unlock(&_this->stateMutex);
					}
				}
				else{
					delete packet;
					pthread_mutex_unlock(&_this->stateMutex);
				}
				break;
			
			case SVC_CMD_CONNECT_INNER7:				
				//-- authenticated
				pthread_mutex_lock(&_this->stateMutex);
				_this->state = SVC_CMD_CONNECT_INNER7;
				_this->isAuth = true;
				packet->setCommand(SVC_CMD_CONNECT_OUTER3);
				packet->packet[INFO_BYTE] |= SVC_ENCRYPTED;
				_this->inetOutgoingQueue.enqueue(packet);
				pthread_mutex_unlock(&_this->stateMutex);
				break;							
			
			case SVC_CMD_CONNECT_INNER9:
				//-- connection established
				pthread_mutex_lock(&_this->stateMutex);
				_this->state = SVC_CMD_CONNECT_INNER9;
				_this->isAuth = true;
				delete packet;
				pthread_mutex_unlock(&_this->stateMutex);
				break;
			
			default:
				delete packet;
				break;
		}
	}
	else{
		//-- mark to be encrypted
		packet->packet[INFO_BYTE] |= SVC_ENCRYPTED;				
		_this->inetOutgoingQueue.enqueue(packet);
	}
}


//================================	DAEMON CODE ==============================

void* daemon_unix_reading_loop(void* args){	
	//-- read from unix socket then enqueue to incoming queue
	uint8_t buffer[SVC_DEFAULT_BUFSIZ] = "";
	ssize_t readrs;
		
	while (working){
		readrs = recv(daemonUnSocket, buffer, SVC_DEFAULT_BUFSIZ, 0);		
		if (readrs>0){
			//cout<<"\ndaemon_unix_reading_loop read a packet: "); printBuffer(buffer, readrs);
			daemonUnixIncomingQueue.enqueue(new SVCPacket(buffer, readrs));
		}
		//else: read received nothing
	}
	pthread_exit(EXIT_SUCCESS);
}

void* daemon_inet_reading_loop(void* args){
	struct sockaddr_in srcAddr;
	socklen_t srcAddrLen;
	int readrs;
	SVCPacket* packet;
	
	uint8_t buffer[SVC_DEFAULT_BUFSIZ];

	while (working){
		srcAddrLen = sizeof(srcAddr);		
		readrs = recvfrom(daemonInSocket, buffer, SVC_DEFAULT_BUFSIZ, 0, (struct sockaddr*)&srcAddr, &srcAddrLen);		
		if (readrs>0){
			//cout<<"\ndaemon_inet_reading_loop read a packet: "); printBuffer(buffer, readrs);
			packet = new SVCPacket(buffer, readrs);
			packet->setSrcAddr((struct sockaddr_storage*)&srcAddr, srcAddrLen);			
			daemonInetIncomingQueue.enqueue(packet);
			//cout<<"."); fflush(stdout);
		}
	}
	pthread_exit(EXIT_SUCCESS);
}

void shutdownDaemon(){
	if (working){		
		working = false;
		//-- request all daemon endpoint to shutdown
		for (auto& it : endpoints){
			if (it.second != NULL){
				DaemonEndpoint* ep = (DaemonEndpoint*)it.second;
				endpoints[ep->endpointID] = NULL;
				delete ep; //-- destructor calls shutdown
			}
		}
		endpointChecker->stopWorking();
		
		//-- stop reading packets
		shutdown(daemonUnSocket, SHUT_RD);
		shutdown(daemonInSocket, SHUT_RD);
		pthread_join(daemonInetReadingThread, NULL);
		pthread_join(daemonUnixReadingThread, NULL);

		//-- process leftover packets
		daemonUnixIncomingPacketHandler->stopWorking();
		daemonInetIncomingPacketHandler->stopWorking();
	}
}

void signal_handler(int sig){
	if (sig == SIGINT){
		shutdownDaemon();
	}	
}



void daemon_inet_incoming_packet_handler(SVCPacket* packet, void* args){

	static uint8_t param[SVC_DEFAULT_BUFSIZ] = "";
	static uint16_t paramLen;
	
	if (packet->dataLen>SVC_PACKET_HEADER_LEN){
		uint8_t infoByte = packet->packet[INFO_BYTE];
		uint64_t endpointID = *((uint64_t*)(packet->packet+1));
	
		if ((infoByte & SVC_COMMAND_FRAME) != 0x00){
			if ((infoByte & SVC_ENCRYPTED)!=0x00){
				if (endpoints[endpointID] != NULL && endpoints[endpointID]->working){
					//-- forward packet if endpoint found
					//cout<<"\nforwarding encrypted command packet (OUTER3)"); fflush(stdout);
					endpoints[endpointID]->inetIncomingQueue.enqueue(packet);
				}
				else{
					delete packet;
				}
			}
			else{
				enum SVCCommand cmd = (enum SVCCommand)packet->packet[CMD_BYTE];			
				uint64_t newEndpointID = 0;
				uint32_t appID;
				string appSockPath;
				DaemonEndpoint* dmnEndpoint;
				SVCPacket* encryptedECPoint;
			
				//-- TODO: check if packet's address is the same as connected, if not updates
				
				struct sockaddr_un appSockAddr;	
				memset(&appSockAddr, 0, sizeof(appSockAddr));
				appSockAddr.sun_family = AF_LOCAL;
		
				int sendrs;
	
				switch (cmd){
					case SVC_CMD_CONNECT_OUTER1:
						//-- extract DH-1
						if (!packet->popDataChunk(param, &paramLen)){
							delete packet;
							break;
						}
						encryptedECPoint = new SVCPacket(param, paramLen);
					
						newEndpointID |= ++daemonEndpointCounter;
						newEndpointID <<= 48;
						newEndpointID |= endpointID;
						//-- create new daemonEndpoint for this endpointID
						dmnEndpoint = new DaemonEndpoint(newEndpointID);
						endpoints[newEndpointID] = dmnEndpoint;				
						dmnEndpoint->connectToAddress((struct sockaddr_in*)&packet->srcAddr, packet->srcAddrLen);
						if (dmnEndpoint->startInetHandlingRoutine()!=0){
							delete packet;
							dmnEndpoint->working = false;
							break;
						}
						dmnEndpoint->encryptedECPoint = encryptedECPoint;
					
						//-- extract appID
						if (!packet->popDataChunk(param, &paramLen)){
							delete packet;
							dmnEndpoint->working = false;
							break;
						}
						appID = *((uint32_t*)param);					
					
						//-- send the packet to the corresponding app
						packet->setCommand(SVC_CMD_CONNECT_INNER2);					
						appSockPath = string(SVC_CLIENT_PATH_PREFIX) + to_string(appID);
						appSockAddr.sun_path[0] = '\0';
						memcpy(appSockAddr.sun_path+1, appSockPath.c_str(), appSockPath.size());
						//-- replace the oldEndpointID by the newEndpointID
						memcpy(packet->packet+1, (uint8_t*)&newEndpointID, ENDPOINTID_LENGTH);
						sendrs = sendto(daemonUnSocket, packet->packet, packet->dataLen, 0, (struct sockaddr*)&appSockAddr, sizeof(appSockAddr));
						delete packet;
						break;
			
					case SVC_CMD_CONNECT_OUTER2:
						//-- newEndpointID contains old ID			
						newEndpointID = endpointID;
						endpointID = newEndpointID & 0x0000FFFFFFFFFFFF;			
						if (endpoints[endpointID] != NULL && (!endpoints[endpointID]->isAuth)){				
							endpoints[newEndpointID] = endpoints[endpointID];
							//-- remove old record
							endpoints[endpointID] = NULL;
							//--	update endpointID
							endpoints[newEndpointID]->endpointID = newEndpointID;
					
							//-- forward packet
							endpoints[newEndpointID]->inetIncomingQueue.enqueue(packet);
						}
						else{
							delete packet;
						}
						break;
			
					default:
						//-- ignore other command that not be encrypted
						delete packet;
						break;
				}
			}
		}
		else{
			//-- incoming data, discard if not encrypted or endpoint not found		
			if ((endpoints[endpointID] == NULL) || ((infoByte & SVC_ENCRYPTED) == 0x00) || !endpoints[endpointID]->working || (endpoints[endpointID]->aesgcm==NULL)){
				delete packet;
			}
			else{
				//forward packet to inetIncomingQueue			
				endpoints[endpointID]->inetIncomingQueue.enqueue(packet);
			}
		}
	}
	else{
		//-- packet's length not valid
		delete packet;
	}
}

void checkEndpointLiveTime(void* args){

	for (auto& it : endpoints){		
		if (it.second != NULL){
			DaemonEndpoint* ep = (DaemonEndpoint*)it.second;
			bool removeEndpoint = false;
			if (!ep->working){
				removeEndpoint = true;
			}
			else{
				if (!ep->isAuth && !ep->checkInitLiveTime(1000)){
					removeEndpoint = true;
				}
				else{
					if (ep->beatUp){
						ep->beatUp = false;
					}
					else{
						ep->beatLiveTime--;
					}
					removeEndpoint = (ep->beatLiveTime < 0);
				}
			}			
			if (removeEndpoint){
				endpoints[ep->endpointID] = NULL;				
				delete ep;
			}
		}
	}
}
*/
