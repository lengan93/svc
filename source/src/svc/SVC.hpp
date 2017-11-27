/* Secure Virtual Connector (SVC) protocol header */

#ifndef __SVC__
#define __SVC__

	#include "svc-utils.h"
	#include "host/SVCHost.h"
	#include "authenticator/SVCAuthenticator.h"
	
	#include "../utils/MutexedQueue.h"
	#include "../utils/PeriodicWorker.h"

	#include "../crypto/crypto-utils.h"
	#include "../crypto/AES256.h"
	#include "../crypto/SHA256.h"
	#include "../crypto/ECCurve.h"
	#include "../crypto/AESGCM.h"

	#include <csignal>
	#include <sys/un.h>
	#include <sys/socket.h>	
	#include <unordered_map>

	#include "transport/udp.hpp"
	
	#define RECONNECTION_TIMEOUT	5000

	//--	FORWARD DECLARATION		--//
	class SVC;
		
	class SVCEndpoint{				
		friend class SVC;

		private:
			// for debug only			
			int sendCounter = 0;
			int recvCounter = 0;

			// SVC* svc;
			bool isInitiator;
			bool isAuth;
			PeriodicWorker* periodicWorker;
			
			volatile bool working;
			volatile bool shutdownCalled;
			int reconnectionTimeout;			
			bool reconnectFailed;
			string daemonRestartReason;

			// static void liveCheck(void* args);		
			// static void svc_endpoint_incoming_packet_handler(SVCPacket* packet, void* args);
			// //static void svc_endpoint_outgoing_packet_handler(SVCPacket* packet, void* args);
			// static void* svc_endpoint_reading_loop(void* args);
			// static void* svc_endpoint_writing_loop(void* args);
			
			pthread_t readingThread;
			pthread_t writingThread;
			//MutexedQueue<SVCPacket*> incomingQueue;
			//MutexedQueue<SVCPacket*> outgoingQueue;
			MutexedQueue<SVCPacket*>* tobesentQueue;
			MutexedQueue<SVCPacket*>* dataholdQueue;
			PacketHandler* incomingPacketHandler;
			//PacketHandler* outgoingPacketHandler;
			
			int sockOption;
			TransportHandler* transport;

			uint64_t endpointID;
			uint32_t appID;			
			SVCHost* remoteHost;
			SVCPacket* request;
			
			//-- crypto negotitation
			std::string challengeSecretSent;
			std::string challengeSecretReceived;
			std::string challengeSent;
			std::string challengeReceived;
			std::string proof;
			std::string remoteIdentity;
		
			SVCEndpoint(uint64_t endpointID, bool isInitiator) {
				// this->svc = svc;
				this->endpointID = endpointID;
				this->isInitiator = isInitiator;
				transport = new UDP();	
			}
			
			/*
			 * Connect the unix domain socket to the daemon endpoint address to send data
			 * */
			// int connectToDaemon();
			
			/*
			 * After a disconnection with daemon is detected, calling this method will try to reconnect with the daemon. 
			 * If TRUE is returned,the reconnection succeeded. Otherwise, the reconnection
			 * is failed and SVC must be shutdown. The default waiting time can be set via setReconnectionTimeout.
			 * */
			// bool reconnectDaemon();
			
			/*
			 * */
			void setRemoteHost(SVCHost* remoteHost){
				transport->connect_to(remoteHost);
			}
			
			void listen() {
				transport->listen();
				this->request = receive_packet();
			}
			
			/*
			 * */
			void changeEndpointID(uint64_t endpointID) {}		

			int send_packet(SVCPacket* packet) {
				return transport->sendData(packet->packet, packet->dataLen);
			}

			SVCPacket* receive_packet() {
				SVCPacket* packet = new SVCPacket();
				transport->recvData(packet->packet, packet->dataLen);
				return packet;
			}			

		public:
			~SVCEndpoint();
			/*
			 * Start negotiating and return TRUE if the protocol succeeds, otherwise return FALSE
			 * */
			bool negotiate(SVCAuthenticator* authenticator) {
				SVCPacket * packet;

				SHA256 sha256;
				AES256* aes256;
				AESGCM* aesgcm;

				int requested_security_strength;
				ECCurve* curve = new ECCurve();
				mpz_t randomX;
				ECPoint* ecpoint;
				ECPoint* gxy;
				uint8_t* iv;
				uint16_t ivLen;
				
				uint8_t aeskey[KEY_LENGTH];

				uint8_t* tag;
  			 	uint16_t tagLen;

				uint8_t* decrypted;
  				uint32_t decryptedLen;

				mpz_t randomNumber;

				uint8_t solutionProof[SVC_DEFAULT_BUFSIZ];
  			 	uint16_t solutionProofLen;

				string hashValue;
				char ecpointHexString[SVC_DEFAULT_BUFSIZ];
				uint16_t paramLen;
				uint8_t param[SVC_DEFAULT_BUFSIZ];
				uint16_t ecpointHexLen;	
				uint8_t* encrypted;
				uint32_t encryptedLen;
				uint8_t* data;
				uint32_t dataLen;

				SVCPacket* encryptedECPoint;
				SVCPacket* encryptedProof;

				if (this->isInitiator){
					//-- get challenge secret and challenge		
					this->challengeSecretSent = authenticator->generateChallengeSecret();		
					// cout << "challengeSecretSent: " <<this->challengeSecretSent << endl;

					// SHA256 sha;
					// std::string dg = sha.hash(this->challengeSecretSent);
					// cout << "expected hash: " << dg <<endl;

					this->challengeSent = authenticator->generateChallenge(challengeSecretSent);		
					
					// packet->pushCommandParam((uint8_t*)&this->svc->appID, APPID_LENGTH);
					// packet->pushCommandParam((uint8_t*)challengeSecretSent.c_str(), challengeSecretSent.size());
					// uint32_t remoteAddr = this->remoteHost->getHostAddress();
					// packet->pushCommandParam((uint8_t*)&remoteAddr, HOST_ADDR_LENGTH);
					
					// from daemon
					//-- extract challengeSecret x
					// packet->popCommandParam(param, &paramLen);
					//-- use SHA256(x) as an AES256 key
					hashValue = sha256.hash(challengeSecretSent.c_str());
					stringToHex(hashValue, aeskey); //AES key is guaranteed to be 256 bits length
					if (aes256!=NULL) delete aes256;
					aes256 = new AES256(aeskey);
					
					//-- generate STS-gx
					requested_security_strength = curve->getRequestSecurityLength();					
					generateRandomNumber(&randomX, requested_security_strength);
					ecpoint = new ECPoint();
					curve->mul(ecpoint, curve->g, &randomX);
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

					packet = new SVCPacket(this->endpointID);
					packet->pushCommandParam((uint8_t*)challengeSent.c_str(), challengeSent.size());
					packet->pushCommandParam(encrypted, encryptedLen);
					
					free(encrypted);
					delete aes256;
					delete ecpoint;
					
					//-- switch commandID
					// packet->switchCommand(SVC_CMD_CONNECT_OUTER1);
					//-- send the packet to internet					
					this->send_packet(packet);
					delete packet;
					//this->outgoingQueue->enqueue(packet);
					// this->tobesentQueue->enqueue(packet);
					
					// wait for the response
					// packet = this->dataholdQueue->dequeueWait(timeout);
					packet = receive_packet();

					if (!packet->popCommandParam(param, &paramLen)){
						delete packet;
						
					}
					encryptedProof = new SVCPacket(param, paramLen);
				
					if (!packet->popCommandParam(param, &paramLen)){
						delete encryptedProof;
						delete packet;
						
					}
					encryptedECPoint = new SVCPacket(param, paramLen);
	
					//-- change command to INNER_4				
					// packet->switchCommand(SVC_CMD_CONNECT_INNER4);
					//-- app svc is still waiting for the 'old' endpointID, push the current endpointID as new param
					// packet->pushCommandParam(packet->packet+1, ENDPOINTID_LENGTH);
					// //-- clear the 6&7 byte of endpointID
					// packet->packet[1+6]=0x00;
					// packet->packet[1+7]=0x00;				
					// _this->unixOutgoingQueue.enqueue(packet);

					// //--	new endpointID
					// packet->popCommandParam(param, &paramLen);
					// _this->changeEndpointID(*((uint64_t*)param));
					//-- replace packet endpointID with the new one
					// memcpy(packet->packet+1, param, ENDPOINTID_LENGTH);		

					packet->popCommandParam(param, &paramLen);
					challengeReceived = std::string((char*)param, paramLen);
					
					//--	resolve challenge then send back to daemon
					challengeSecretReceived = authenticator->resolveChallenge(challengeReceived);
					// cout << "SVC_CMD_CONNECT_INNER4 challengeSecretReceived: "_this->challengeSecretReceived <<endl;
					//- packet updated with new endpointID
					// packet->switchCommand(SVC_CMD_CONNECT_INNER5);				
					// packet->pushCommandParam((uint8_t*)_this->challengeSecretReceived.c_str(), _this->challengeSecretReceived.size());
					//_this->outgoingQueue->enqueue(packet);
					// _this->tobesentQueue->enqueue(packet);

					// if (!packet->popCommandParam(solution, &solutionLen)){
					// 	delete packet;
					// 	pthread_mutex_unlock(&_this->stateMutex);
					// 	break;
					// }
			
					//-- hash this solution to create the aes256 key to decrypt encryptedECPoint from CONNECT_OUTER2
					hashValue = sha256.hash(string(challengeSecretReceived.c_str(), challengeSecretReceived.size()));
					stringToHex(hashValue, aeskey); //-- aes key used to decrypt k1
					aes256 = new AES256(aeskey);
					aes256->decrypt(encryptedECPoint->packet, encryptedECPoint->dataLen, &data, &dataLen);
				
					delete aes256;
					//-- construct gy from decrypted k2
			
					paramLen = *((uint16_t*)data);				
					//-- !! check these gy_x and gy_y
					if ((data[1+paramLen] == 0x00) && (data[dataLen-1] == 0x00)){
						ecpoint = new ECPoint((char*)(data + 2) , (char*)(data + 4 + paramLen));
						free(data);
						//-- generate shared secret gxy
						gxy = new ECPoint();
						curve->mul(gxy, ecpoint, &randomX);					
						delete ecpoint;
				
						//-- generate aesgcm to decrypt solution proof
						mpz_get_str(ecpointHexString, 16, gxy->x);
						ecpointHexLen = strlen(ecpointHexString);
						memcpy(param, ecpointHexString, ecpointHexLen);
						paramLen = ecpointHexLen;					
				
						mpz_get_str(ecpointHexString, 16, gxy->x);
						ecpointHexLen = strlen(ecpointHexString);
						memcpy(param + paramLen , ecpointHexString, ecpointHexLen);
						paramLen += ecpointHexLen;	
					
						delete gxy;			
				
						if (aesgcm == NULL){
							//-- aesgcm key = hash(gxy.x || gxy.y)
							hashValue = sha256.hash(string((char*)param, paramLen));
							stringToHex(hashValue, aeskey);						
							aesgcm = new AESGCM(aeskey, (enum SecurityParameter)requested_security_strength);
						
							//-- decrypt the solution proof
							iv = encryptedProof->packet+2;
							ivLen = *((uint16_t*)encryptedProof->packet);						
							encrypted = encryptedProof->packet + 4 + ivLen;
							encryptedLen = *((uint16_t*)(encryptedProof->packet + 2 + ivLen));								
							tag = encryptedProof->packet + 6 + ivLen + encryptedLen;
							tagLen = *((uint16_t*)(encryptedProof->packet + 4 + ivLen + encryptedLen));						
							if (aesgcm->decrypt(iv, ivLen, encrypted, encryptedLen, NULL, 0, tag, tagLen, &decrypted, &decryptedLen)){
								//-- solution proof decrypted succeeded by aesgcm							
								//-- forward CONNECT_INNER6 to app
								// packet->switchCommand(SVC_CMD_CONNECT_INNER6);
								// packet->pushCommandParam(decrypted, decryptedLen);	
								// state = SVC_CMD_CONNECT_INNER5;											
								// unixOutgoingQueue.enqueue(packet);
								if (authenticator->verifyProof(challengeSecretSent, std::string((char*)encrypted, encryptedLen))){
									//-- proof verified, generate proof then send back to daemon
									proof = authenticator->generateProof(challengeSecretReceived);
									// packet->switchCommand(SVC_CMD_CONNECT_INNER7);				
									packet->pushCommandParam((uint8_t*)proof.c_str(), proof.size());
									//outgoingQueue->enqueue(packet);
									tobesentQueue->enqueue(packet);
									//-- ok, connection established
									// printf("\n2\n");						
									isAuth = true;
								}
								else{					
									//-- proof verification failed
									delete packet;
									// printf("\n3\n");						
									isAuth = false;
								}

							}
						}


					// if (!this->incomingPacketHandler->waitCommand(SVC_CMD_CONNECT_INNER4, this->endpointID, SVC_DEFAULT_TIMEOUT)){
					// 	this->isAuth = false;
					// }
					// else{
					// 	if (!this->incomingPacketHandler->waitCommand(SVC_CMD_CONNECT_INNER6, this->endpointID, SVC_DEFAULT_TIMEOUT)){
					// 		this->isAuth = false;
					// 	}
					}
				}
				else{
					//-- read challenge from request packet
					// printf("negotiate server\n");
					this->request->popCommandParam(param, &paramLen);
					this->challengeReceived = std::string((char*)param, paramLen);
					
					//-- resolve this challenge to get challenge secret
					this->challengeSecretReceived = authenticator->resolveChallenge(this->challengeReceived);
					this->remoteIdentity = authenticator->getRemoteIdentity(this->challengeSecretReceived);
					// cout << "challengeSecretReceived: " << this->challengeSecretReceived << endl;

					//-- generate proof
					this->proof = authenticator->generateProof(this->challengeSecretReceived);		
					// cout << "proof: " << this->proof <<endl;

					//-- generate challenge
					this->challengeSecretSent = authenticator->generateChallengeSecret();		
					this->challengeSent = authenticator->generateChallenge(this->challengeSecretSent);		
					// cout<< "challengeSecretSent: " << this->challengeSecretSent <<endl;

					// packet->setCommand(SVC_CMD_CONNECT_INNER3);
					// packet->pushCommandParam((uint8_t*)this->challengeSent.c_str(), this->challengeSent.size());
					// packet->pushCommandParam((uint8_t*)this->proof.c_str(), this->proof.size());
					// packet->pushCommandParam((uint8_t*)this->challengeSecretSent.c_str(), this->challengeSecretSent.size());
					// packet->pushCommandParam((uint8_t*)this->challengeSecretReceived.c_str(),  this->challengeSecretReceived.size());
					// //this->outgoingQueue->enqueue(packet);
					// this->tobesentQueue->enqueue(packet);
					
					hashValue = sha256.hash(challengeSecretReceived);
					stringToHex(hashValue, aeskey); //-- aes key used to decrypt k1
				
					aes256 = new AES256(aeskey);				
					aes256->decrypt(encryptedECPoint->packet, encryptedECPoint->dataLen, &data, &dataLen);
				
					//-- construct gx from decrypted K1				
					paramLen = *((uint16_t*)data);
					
					//-- !! check if the decrypt ecpoint data is at least VALID, by verifying the null-terminator at the end of each number
					//-- otherwise the new ECPoint will be created with buffer-overflow error

					if ((data[1+paramLen] == 0x00) && (data[dataLen-1] == 0x00)){

						ecpoint = new ECPoint((char*)(data + 2) , (char*)(data + 4 + paramLen));				
						//-- extract challengeSecret y
						if (!packet->popCommandParam(param, &paramLen)){
							free(data);
							delete aes256;
							delete packet;
							delete ecpoint;
							// break;
						}
						//-- use SHA256(y) as an AES256 key
						hashValue = sha256.hash(string((char*)param, paramLen));
						//-- create new aes key to encrypt
						stringToHex(hashValue, aeskey);
						delete aes256;
						aes256 = new AES256(aeskey);
					
						//-- generate random number y
						if (curve == NULL) curve = new ECCurve();					
						requested_security_strength = curve->getRequestSecurityLength();
						mpz_init(randomNumber);
						generateRandomNumber(&randomNumber,requested_security_strength);			
						//-- generate shared secret gxy			
						gxy = new ECPoint();
						curve->mul(gxy, ecpoint, &randomNumber);					
									
						mpz_get_str(ecpointHexString, 16, gxy->x);
						ecpointHexLen = strlen(ecpointHexString);
						memcpy(param, ecpointHexString, ecpointHexLen);
						paramLen = ecpointHexLen;					
				
						mpz_get_str(ecpointHexString, 16, gxy->x);
						ecpointHexLen = strlen(ecpointHexString);
						memcpy(param + paramLen , ecpointHexString, ecpointHexLen);
						paramLen += ecpointHexLen;
					
						delete gxy;
					
						if (aesgcm == NULL){
							//-- aesgcm key = hash(gxy.x || gxy.y)
							hashValue = sha256.hash(string((char*)param, paramLen));
							stringToHex(hashValue, aeskey);
							aesgcm = new AESGCM(aeskey, (enum SecurityParameter)requested_security_strength);					
						}
					
						//-- pop solution proof to be encrypted
						if (!packet->popCommandParam(solutionProof, &solutionProofLen)){
							free(data);
							delete aesgcm;
							aesgcm = NULL;
							delete packet;
							delete aes256;
							delete ecpoint;	
							// pthread_mutex_unlock(&stateMutex);					
							// break;
						}
				
						//-- gererate STS-gy
						curve->mul(ecpoint, curve->g, &randomNumber);
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
						packet->switchCommand(SVC_CMD_CONNECT_OUTER2);
						//-- attach Ey(gy) to packet
						packet->pushCommandParam(encrypted, encryptedLen);					
						free(encrypted);
				
						//-- encrypt solution proof then attach to packet
						//-- generate random iv, the first 2 byte are used to store ivLen				
						generateRandomData(requested_security_strength, param + 2);
				
						aesgcm->encrypt(param + 2, requested_security_strength, solutionProof, solutionProofLen, NULL, 0, &encrypted, &encryptedLen, &tag, &tagLen);					
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
						packet->pushCommandParam(param, paramLen);
						free(encrypted);
						free(tag);
						delete aes256;
						// state = SVC_CMD_CONNECT_INNER3;
						// pthread_mutex_unlock(&stateMutex);
						//-- send this packet to internet
						send_packet(packet);
					}

					//-- wait for the last message 
					packet = receive_packet();
					packet->popCommandParam(param, &paramLen);
					if (authenticator->verifyProof(challengeSecretSent, std::string((char*)param, paramLen))){
						//-- send confirm to daemon
						// packet->setCommand(SVC_CMD_CONNECT_INNER9);					
						//outgoingQueue->enqueue(packet);
						// tobesentQueue->enqueue(packet);
						// printf("\n5\n");						
						isAuth = true;
					}
					else{
						//-- proof verification failed
						delete packet;
						// printf("\n6\n");						
						isAuth = false;
					}

					// if (!this->incomingPacketHandler->waitCommand(SVC_CMD_CONNECT_INNER8, this->endpointID, SVC_DEFAULT_TIMEOUT)){
					// 	this->isAuth = false;
					// }
				}
				// free(param);
				return this->isAuth;
			}
			
			/*
			 *
			 * */
			// std::string getRemoteIdentity();
						
			/*
			 * Send data over the connector to the other endpoint of communication.
			 * The data will be automatically encrypted by the under layer
			 * */			 						 
			int sendData(const uint8_t* data, uint32_t dalalen) {
				return 0;
			}

			int sendData(const uint8_t* data, uint32_t datalen, uint8_t option){
				return 0;
			}
			
			/*
			 * Read data from the buffer. The data had already been decrypted by lower layer
			 * */
			int readData(uint8_t* data, uint32_t* len, int timeout){
				
				return 0;				
			}
			
			/*
			 * Close the communication endpoint and send terminate signals to underlayer
			 * */
			void shutdownEndpoint(){}
			
			/*
			 * Set the timeout of reconnection method in case of losing connection with the daemon. 'timeout' cannot be set to negative.
			 * */
			void setReconnectionTimeout(int timeout){}
			
			bool isAlive(){
				return this->isAuth;
			}
	};
	
	class SVC {
		friend class SVCEndpoint;

		private:
			//-- static members
			static uint16_t endpointCounter;
			
			static void svc_incoming_packet_handler(SVCPacket* packet, void* args);
			//static void svc_outgoing_packet_handler(SVCPacket* packet, void* args);
			static void* svc_reading_loop(void* args);
			//static void* svc_writing_loop(void* args);
			
			//-- private members
			inline void sendPacketToDaemon(SVCPacket* packet);
			
			volatile bool working;
			volatile bool shutdownCalled;
			pthread_t readingThread;
			//pthread_t writingThread;			
			//MutexedQueue<SVCPacket*>* incomingQueue;
			//MutexedQueue<SVCPacket*>* outgoingQueue;
			//MutexedQueue<SVCPacket*>* tobesentQueue;
			MutexedQueue<SVCPacket*>* connectionRequests;
			
			PacketHandler* incomingPacketHandler;
			//PacketHandler* outgoingPacketHandler;
															
			unordered_map<uint64_t, SVCEndpoint*> endpoints;
			
			SHA256* sha256;
			int appSocket;
			uint32_t appID;
			SVCAuthenticator* authenticator;
			
		public:
			
			/*
			 * Create a SVC instance which is used by 'appID' and has 'authenticator' as protocol authentication mechanism
			 * */
			SVC(std::string appID, SVCAuthenticator* authenticator) {
				this->authenticator = authenticator;

			}
						
			~SVC();
			
			/*
			 * establishConnection immediately returns a pointer of SVCEndpoint that will later be used to perform the protocol's negotiation
			 * Because the negotiation takes time, it is highly recommended to start it in a seperated thread
			 * */
			SVCEndpoint* establishConnection(SVCHost* remoteHost, uint8_t option) {
				uint64_t endpointID = 0;	
				endpointID |= ++SVC::endpointCounter;
				endpointID<<=32;
				SVCEndpoint* endpoint = new SVCEndpoint(endpointID, true);
				endpoint->sockOption = option;
				endpoint->setRemoteHost(remoteHost);
				
				if(endpoint->negotiate(authenticator)){
				
					//-- add this endpoint to be handled
					this->endpoints[endpoint->endpointID] = endpoint;
					return endpoint;
				}
				else {

					return NULL;
				}

			}
			
			/*
			 * 'listenConnection' reads in the connection request queue and returns immediately if a request is found
			 * If there is no connection request, 'listenConnection' will wait for 'timeout' milisecond before return NULL		
			 * On success, a pointer to SVCEndpoint is returned
			 * */
			SVCEndpoint* listenConnection(int timeout){
				SVCEndpoint* endpoint = new SVCEndpoint(0, false);
				endpoint->listen();
				if(endpoint->negotiate(authenticator)){
				
					//-- add this endpoint to be handled
					this->endpoints[endpoint->endpointID] = endpoint;
					return endpoint;
				}
				else {

					return NULL;
				}	
			}
			
			/*
			 * try to shutdown all created instances of SVCEndpoint then shutdown itself
			 * */
			void shutdownSVC();
	};
	
	uint16_t SVC::endpointCounter = 0;

#endif
