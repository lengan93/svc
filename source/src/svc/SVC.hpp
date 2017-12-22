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
	// #include "../crypto/AESGCM.h"
	#include "../crypto/AESGCM-openssl.hpp"

	#include <csignal>
	#include <sys/un.h>
	#include <sys/socket.h>	
	#include <unordered_map>

	#include "transport/udp.hpp"
	#include "transport/tcp.hpp"
	
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
			
			AESGCM_SSL* aesgcm;
			// AESGCM* aesgcm;

			SVCEndpoint(uint64_t endpointID, bool isInitiator, TransportProto proto) {
				// this->svc = svc;
				this->endpointID = endpointID;
				this->isInitiator = isInitiator;
				switch(proto) {
					case PROTO_UDP:
						transport = new UDP();
						break;
					case PROTO_TCP:
						transport = new TCP();
						break;
					case PROTO_HTP:
						transport = new UDP();
						break;
					default:
						throw "unknown transport protocol";
				}
					
			}
			
			/*
			 * */
			void setRemoteHost(SVCHost* remoteHost){
				transport->connect_to(remoteHost);
			}
			
			void listen(int port) {
				transport->listen(port);
				this->request = receive_packet();
			}
			
			/*
			 * */
			void changeEndpointID(uint64_t endpointID) {}		

			int send_packet(SVCPacket* packet) {
				int r = transport->sendData(packet->packet, packet->dataLen);
				return r;
			}

			SVCPacket* receive_packet() {
				SVCPacket* packet = new SVCPacket();
				transport->recvData(packet->packet, &packet->dataLen);
				// printBuffer(packet->packet, packet->dataLen);
				return packet;
			}	

			void encryptPacket(SVCPacket* packet){

				uint8_t* iv = packet->packet+ENDPOINTID_LENGTH+1;
				uint16_t ivLen = SEQUENCE_LENGTH;	
				
				uint8_t* tag;
				uint16_t tagLen;	
				uint8_t* encrypted;
				uint32_t encryptedLen;

				//-- set infoByte
				packet->packet[INFO_BYTE] |= SVC_ENCRYPTED;
				
				// aesgcmMutex.lock();
				// this->aesgcm->encrypt(iv, ivLen, packet->packet+SVC_PACKET_HEADER_LEN, packet->dataLen - SVC_PACKET_HEADER_LEN, packet->packet, SVC_PACKET_HEADER_LEN, &encrypted, &encryptedLen, &tag, &tagLen);
				this->aesgcm->encrypt(iv, ivLen, packet->packet+SVC_PACKET_HEADER_LEN, packet->dataLen - SVC_PACKET_HEADER_LEN, packet->packet, SVC_PACKET_HEADER_LEN, &encrypted, encryptedLen, &tag);
				// aesgcmMutex.unlock();
				
				//-- set body to be encrypted
				packet->setBody(encrypted, encryptedLen);
				//-- copy tag and tagLen to the end of packet
				packet->pushCommandParam(tag, 16);	
				

				free(encrypted);
				free(tag);
			}

			bool decryptPacket(SVCPacket* packet){
				bool rs;
				uint8_t* iv = (uint8_t*)(packet->packet + ENDPOINTID_LENGTH + 1);
				uint16_t ivLen = SEQUENCE_LENGTH;
				uint8_t* aad = packet->packet;
				uint16_t aadLen = SVC_PACKET_HEADER_LEN;	
				
				uint16_t tagLen = *((uint16_t*)(packet->packet+packet->dataLen - 2));
				uint8_t* tag = packet->packet+packet->dataLen-2-tagLen;
				
				uint8_t* decrypted;
				uint32_t decryptedLen;
				
				// aesgcmMutex.lock();
				// rs = this->aesgcm->decrypt(iv, ivLen, packet->packet+SVC_PACKET_HEADER_LEN, packet->dataLen - SVC_PACKET_HEADER_LEN - 2 - tagLen, aad, aadLen, tag, tagLen, &decrypted, &decryptedLen);
				this->aesgcm->decrypt(iv, ivLen, packet->packet+SVC_PACKET_HEADER_LEN, packet->dataLen - SVC_PACKET_HEADER_LEN - 2 - tagLen, aad, aadLen, tag, &decrypted, decryptedLen);
				// aesgcmMutex.unlock();

				//-- set body to be decrypted
				if (decryptedLen > 0){
					packet->setBody(decrypted, decryptedLen);
					packet->packet[INFO_BYTE] &= ~SVC_ENCRYPTED;
					free(decrypted);
					return true;
				}
				return false;
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

				int requested_security_strength;
				ECCurve* curve = new ECCurve();
				mpz_t randomX;
				mpz_t randomNumber;
				ECPoint* ecpoint;
				ECPoint* gxy;
				uint8_t* iv;
				uint16_t ivLen;
				
				uint8_t aeskey[KEY_LENGTH];

				uint8_t* tag;
  			 	uint16_t tagLen;

				uint8_t* decrypted;
  				uint32_t decryptedLen;

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

				isAuth = false;

				if (this->isInitiator){
					//-- get challenge secret and challenge		
					this->challengeSecretSent = authenticator->generateChallengeSecret();		
					// cout << "challenge secret: " <<challengeSecretSent <<endl;
					// cout << "challengeSecretSent: " <<this->challengeSecretSent << endl;

					this->challengeSent = authenticator->generateChallenge(challengeSecretSent);		
					// cout << "challenge sent: " <<challengeSent <<endl;
					
					//-- use SHA256(x) as an AES256 key
					hashValue = sha256.hash(challengeSecretSent.c_str());
					stringToHex(hashValue, aeskey); //AES key is guaranteed to be 256 bits length
					if (aes256!=NULL) delete aes256;
					aes256 = new AES256(aeskey);
					
					//-- generate STS-gx
					requested_security_strength = curve->getRequestSecurityLength();	
					mpz_init(randomX);
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
					
					// cout << "gx: " << endl;
					// printBuffer(param, paramLen);
					
					// cout << "encrypted gx: " << endl;
					// printBuffer(encrypted, encryptedLen);
					
					packet = new SVCPacket(this->endpointID);
					packet->pushCommandParam(encrypted, encryptedLen);
					packet->pushCommandParam((uint8_t*)challengeSent.c_str(), challengeSent.size());
					
					free(encrypted);
					delete aes256;
					delete ecpoint;
					
					//-- send the packet to internet					
					this->send_packet(packet);
					// cout << "Packet sent: " << endl;
					// printBuffer(packet->packet, packet->dataLen);
					delete packet;
					
					// wait for the response
					packet = receive_packet();

					if (!packet->popCommandParam(param, &paramLen)){
						delete packet;
						return false;
					}
					encryptedProof = new SVCPacket(param, paramLen);
				
					if (!packet->popCommandParam(param, &paramLen)){
						delete encryptedProof;
						delete packet;
						return false;
					}

					// cout << "encrypted gy: " << endl;
					// printBuffer(param, paramLen);

					encryptedECPoint = new SVCPacket(param, paramLen);
	
					packet->popCommandParam(param, &paramLen);
					challengeReceived = std::string((char*)param, paramLen);
					
					//--	resolve challenge
					challengeSecretReceived = authenticator->resolveChallenge(challengeReceived);
					
					// cout << "challengeReceived: " << challengeReceived <<endl;
					// cout << "challengeSecretReceived: " << challengeSecretReceived <<endl;

					//-- hash this solution to create the aes256 key to decrypt encryptedECPoint 
					hashValue = sha256.hash(string(challengeSecretReceived.c_str(), challengeSecretReceived.size()));
					stringToHex(hashValue, aeskey); //-- aes key used to decrypt k1
					aes256 = new AES256(aeskey);
					aes256->decrypt(encryptedECPoint->packet, encryptedECPoint->dataLen, &data, &dataLen);
					
					// cout << "gy: " << endl;
					// printBuffer(data, dataLen);

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
							// aesgcm = new AESGCM(aeskey, (enum SecurityParameter)requested_security_strength);
							aesgcm = new AESGCM_SSL(aeskey);

							cout << "aesgcm key: " <<hashValue <<endl;

							//-- decrypt the solution proof
							iv = encryptedProof->packet+2;
							ivLen = *((uint16_t*)encryptedProof->packet);						
							encrypted = encryptedProof->packet + 4 + ivLen;
							encryptedLen = *((uint16_t*)(encryptedProof->packet + 2 + ivLen));								
							tag = encryptedProof->packet + 6 + ivLen + encryptedLen;
							tagLen = *((uint16_t*)(encryptedProof->packet + 4 + ivLen + encryptedLen));						
							// if (aesgcm->decrypt(iv, ivLen, encrypted, encryptedLen, NULL, 0, tag, tagLen, &decrypted, &decryptedLen)){
							
							// cout<< "encrypted proof (" << encryptedLen<<") :" <<endl;
							printBuffer(encrypted, encryptedLen);

							// cout <<"decrypt tag (" <<tagLen <<"): ";
	    		// 			printBuffer(tag, tagLen);

							if (aesgcm->decrypt(iv, ivLen, encrypted, encryptedLen, NULL, 0, tag, &decrypted, decryptedLen) > 0){
								// cout<< "decrypted proof (" << decryptedLen<<") :" <<endl;
								// printBuffer(decrypted, decryptedLen);
								//-- solution proof decrypted succeeded by aesgcm							
								if (authenticator->verifyProof(challengeSecretSent, std::string((char*)decrypted, decryptedLen))){
									//-- proof verified, generate proof then send back to daemon
									proof = authenticator->generateProof(challengeSecretReceived);
									packet->pushCommandParam((uint8_t*)proof.c_str(), proof.size());

									send_packet(packet);
									
									//-- ok, connection established
									// printf("\n2\n");						
									isAuth = true;
								}
								else {
									cout << "failed 1";
								}

							}
							else {
								cout << "failed 2, proof = " <<decrypted <<endl;
							}
						}
					}
				}
				else{
					//-- read challenge from request packet
					// printf("negotiate server\n");
					// cout << "request received: " << endl;
					// printBuffer(request->packet, request->dataLen);

					this->request->popCommandParam(param, &paramLen);
					this->challengeReceived = std::string((char*)param, paramLen);
					
					//-- resolve this challenge to get challenge secret
					this->challengeSecretReceived = authenticator->resolveChallenge(this->challengeReceived);
					// cout << "challenge recv: " <<challengeReceived <<endl;
					// cout << "challenge secret: " <<challengeSecretReceived <<endl;

					this->remoteIdentity = authenticator->getRemoteIdentity(this->challengeSecretReceived);
					// cout << "challengeSecretReceived: " << this->challengeSecretReceived << endl;

					//-- generate proof
					this->proof = authenticator->generateProof(this->challengeSecretReceived);		
					// cout << "proof: " << this->proof <<endl;

					//-- generate challenge
					this->challengeSecretSent = authenticator->generateChallengeSecret();		
					this->challengeSent = authenticator->generateChallenge(this->challengeSecretSent);		
					// cout<< "challengeSecretSent: " << endl <<this->challengeSecretSent <<endl;
					// cout<< "challengeSent: " << endl <<this->challengeSent <<endl;

					packet = new SVCPacket(this->endpointID);
					packet->pushCommandParam((uint8_t*)challengeSent.c_str(), challengeSent.size());

					hashValue = sha256.hash(challengeSecretReceived);
					stringToHex(hashValue, aeskey); //-- aes key used to decrypt k1
				
					aes256 = new AES256(aeskey);	
					request->popCommandParam(param, &paramLen);
					
					// cout << "encrypted gx: " <<endl;
					// printBuffer(param, paramLen);

					if(aes256->decrypt(param, paramLen, &data, &dataLen)) {
						// cout << "gx: " <<endl;
						// printBuffer(data, dataLen);
					}
					else {
						cout << "aes256 decrypt failed" <<endl;
						return false;
					}
					//-- construct gx from decrypted K1				
					paramLen = *((uint16_t*)data);
					//-- !! check if the decrypt ecpoint data is at least VALID, by verifying the null-terminator at the end of each number
					//-- otherwise the new ECPoint will be created with buffer-overflow error

					if ((data[1+paramLen] == 0x00) && (data[dataLen-1] == 0x00)){

						ecpoint = new ECPoint((char*)(data + 2) , (char*)(data + 4 + paramLen));				
						
						//-- use SHA256(y) as an AES256 key
						hashValue = sha256.hash(challengeSecretSent);
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
							// aesgcm = new AESGCM(aeskey, (enum SecurityParameter)requested_security_strength);					
							aesgcm = new AESGCM_SSL(aeskey);

							cout << "aesgcm key: " <<hashValue <<endl;
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
						
						// cout << "gy :" <<endl;
						// printBuffer(param, paramLen);

						//-- attach Ey(gy) to packet
						packet->pushCommandParam(encrypted, encryptedLen);					
						free(encrypted);
				
						//-- encrypt solution proof then attach to packet
						//-- generate random iv, the first 2 byte are used to store ivLen				
						generateRandomData(requested_security_strength, param + 2);
					
						// cout << "proof (" <<proof.size() <<"): " <<proof <<endl;
						// aesgcm->encrypt(param + 2, requested_security_strength, (uint8_t*) proof.c_str(), proof.size(), NULL, 0, &encrypted, &encryptedLen, &tag, &tagLen);					
						aesgcm->encrypt(param + 2, requested_security_strength, (uint8_t*) proof.c_str(), proof.size(), NULL, 0, &encrypted, encryptedLen, &tag);					
						// cout<< "encrypted proof (" << encryptedLen<<") :" <<endl;
						// printBuffer(encrypted, encryptedLen);

						// cout<< "encrypted tag :" ;
						// printBuffer(tag, 16);

						//-- add iv, encrypted and tag to param	
						tagLen = 16;			
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
						//-- send this packet to internet
						send_packet(packet);

						//-- wait for the last message 
						packet = receive_packet();
						packet->popCommandParam(param, &paramLen);
						if (authenticator->verifyProof(challengeSecretSent, std::string((char*)param, paramLen))){
							isAuth = true;
						}
					}
				}
				// free(param);
				delete packet;
				return this->isAuth;
			}
			
			/*
			 *
			 * */
			// std::string getRemoteIdentity();
						
			/*
			 * 
			 * */			 						 
			int sendData(const uint8_t* data, uint32_t datalen) {
				static uint64_t seq = 0;
				SVCPacket* packet = new SVCPacket(this->endpointID);

				packet->setSequence(seq++);
				packet->setData(data, datalen);
				encryptPacket(packet);
				send_packet(packet);
				delete packet;
				return 0;
			}

			int sendData(const uint8_t* data, uint32_t datalen, uint8_t option){
				
				return 0;
			}
			
			/*
			 * 
			 * */
			int readData(uint8_t* data, uint32_t* len, int timeout){
				SVCPacket* packet = receive_packet();
				if((packet->dataLen > 0) && decryptPacket(packet)) {
					packet->extractData(data, len);
					delete packet;
					return 0;
				}
				return -1;				
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
			
			// static void svc_incoming_packet_handler(SVCPacket* packet, void* args);
			//static void svc_outgoing_packet_handler(SVCPacket* packet, void* args);
			static void* svc_reading_loop(void* args);
			//static void* svc_writing_loop(void* args);
			
			//-- private members
			// inline void sendPacketToDaemon(SVCPacket* packet);
			
			volatile bool working;
			volatile bool shutdownCalled;
			pthread_t readingThread;
			//pthread_t writingThread;			
			//MutexedQueue<SVCPacket*>* incomingQueue;
			//MutexedQueue<SVCPacket*>* outgoingQueue;
			//MutexedQueue<SVCPacket*>* tobesentQueue;
			MutexedQueue<SVCPacket*>* connectionRequests;
			
			// PacketHandler* incomingPacketHandler;
			//PacketHandler* outgoingPacketHandler;
															
			unordered_map<uint64_t, SVCEndpoint*> endpoints;
			
			SHA256* sha256;
			int appSocket;
			uint32_t appID;
			SVCAuthenticator* authenticator;
			TransportProto proto;
			
		public:
			
			/*
			 * Create a SVC instance which is used by 'appID' and has 'authenticator' as protocol authentication mechanism
			 * */
			SVC(std::string appID, SVCAuthenticator* authenticator, TransportProto proto=PROTO_UDP) {
				this->authenticator = authenticator;
				this->proto = proto;
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
				SVCEndpoint* endpoint = new SVCEndpoint(endpointID, true, proto);
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
			SVCEndpoint* listenConnection(int port=SVC_DEFAULT_PORT, int timeout=SVC_DEFAULT_TIMEOUT){
				SVCEndpoint* endpoint = new SVCEndpoint(0, false, proto);
				endpoint->listen(port);
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
