
#include <netinet/in.h>
#include <sys/un.h>
#include <unordered_map>
#include <csignal>
#include <pthread.h>

#include "../htp/HTP.h"
#include "svc-utils.h"
#include "../utils/PeriodicWorker.h"
#include "../crypto/crypto-utils.h"
#include "../crypto/AES256.h"
#include "../crypto/SHA256.h"
#include "../crypto/ECCurve.h"
#include "../crypto/AESGCM.h"

#define SVC_VERSION 0x01
#define PRINT_LOG false

#define _USING_HTP_

using namespace std;

//-- debug stuff
int encryptedSentPackets = 0;
int daemonEpHandledOutPacketCounter = 0;

int readPacketCounter = 0;
int inetWritePacketCounter = 0;
int handledPacketCounter = 0;
int daemonEpHandledInPacketCounter = 0;
int forwardedToAppPacketCounter = 0;
int decryptSuccessPackets =0;

ofstream* DecryptLogfile = new ofstream("decryptfailed.log");
ofstream* EncryptLogfile = new ofstream("rawpackets.log");
char gap[10] = {0};

//--	class forward declaration
class DaemonEndpoint;

//--	GLOBAL VARIABLES
unordered_map<uint64_t, DaemonEndpoint*> endpoints;
struct sockaddr_un daemonSockUnAddress;
struct sockaddr_in daemonSockInAddress;

int daemonUnSocket;

#ifdef _USING_HTP_
	HtpSocket* daemonHtpSocket;
#else
	int daemonInSocket;
#endif

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
		int f;

		//-- crypto protocol variables
		pthread_mutex_t stateMutex;
		SVCCommand state;
		SVCPacket* encryptedECPoint;
		SVCPacket* encryptedProof;
		ECCurve* curve;	
		ECPoint* gxy;
		SHA256 sha256;

		mutex aesgcmMutex;
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
		// printf("\ndaemon endpoint: %d packets received from client", readPacketCounter);
		// printf("\nHTP: %d inet packets sent, %d inet packets received", daemonHtpSocket->sendCounter, daemonHtpSocket->recvCounter);
		
		#ifdef _USING_HTP_
		printf("\n\n========= Sender logs =========");
		printf("\nHTP: %d packets sent successfully, %d packets resended", 
			daemonHtpSocket->successReceivedPackets, daemonHtpSocket->resendPackets);
		// printf("\nDaemon endpoint: %d packets encrypted", encryptedSentPackets);
		// printf("\nDaemon endpoint: %d outgoing inet packets handled", daemonEpHandledOutPacketCounter);
		printf("\n========= /Sender logs =========\n");
		#endif
		
		// printf("\n\n========= Receiver logs =========");
		// printf("\nDaemon: %d inet packets read", readPacketCounter);
		// printf("\nDaemon: %d recvd inet packets handled", handledPacketCounter);
		// printf("\nDaemon endpoint: %d recvd inet packets handled", daemonEpHandledInPacketCounter);
		// printf("\nDaemon endpoint: %d packets decrypted successfully", decryptSuccessPackets);
		// printf("\nDaemon endpoint: %d recvd packets forwarded to App", forwardedToAppPacketCounter);
		// printf("\n========= /Receiver logs =========\n");

		printf("\nendpoint shutdown: "); printBuffer((uint8_t*)&this->endpointID, ENDPOINTID_LENGTH); fflush(stdout);
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
	daemonEpHandledOutPacketCounter++;

	DaemonEndpoint* _this = (DaemonEndpoint*)args;
	uint8_t infoByte = packet->packet[INFO_BYTE];
	if ((infoByte & SVC_ENCRYPTED)!=0x00){
		if (_this->aesgcm!=NULL){
			//-- encrypt packet before send out
			_this->sendSequence++;
			packet->setSequence(_this->sendSequence);
			_this->encryptPacket(packet);

			//JUST FOR TESTING
			// SVCPacket* tmp = new SVCPacket(packet);
			// if((infoByte & SVC_COMMAND_FRAME)==0) {
			// 	bool rs = _this->decryptPacket(tmp);
			// 	if(!rs) {
			// 		printf("sender: failed to decrypt packet %d \n", _this->sendSequence);
			// 	}
			// 	else {
			// 		// printf("decrypted %d \n", _this->sendSequence);
			// 	}
			// }
			// delete tmp;

			_this->inetToBeSentQueue.enqueue(packet);
			encryptedSentPackets++;
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

			if(PRINT_LOG) {
				printf("[%d] send packet %d\n", getTime(), packet->getSequence());
				// printBuffer(packet->packet, packet->dataLen);
			}

			#ifdef _USING_HTP_
				uint8_t flags = 0;
				if((packet->packet[INFO_BYTE] & SVC_NOLOST) != 0) {
					flags = HTP_IMPT;
				}
				sendrs = daemonHtpSocket->sendto(packet->packet, packet->dataLen, flags, (struct sockaddr*)&_this->remoteAddr, _this->remoteAddrLen);			
			#else
				sendrs = sendto(daemonInSocket, packet->packet, packet->dataLen, 0, (struct sockaddr*)&_this->remoteAddr, _this->remoteAddrLen);
			#endif

			inetWritePacketCounter++;

			//printf("\ndaemon inet writes packet %d: errno: %d", sendrs, errno); printBuffer(packet->packet, packet->dataLen); fflush(stdout);
			delete packet;
			//printf("-"); fflush(stdout);
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
	// logPacket(EncryptLogfile, packet->getSequence(), packet->packet, packet->dataLen);
	
	/*//printf("\nencrypt packet with:");
	//printf("\niv: "); printBuffer(iv, ivLen); fflush(stdout);
	//printf("\naad: "); printBuffer(packet->packet, SVC_PACKET_HEADER_LEN); fflush(stdout);
	//printf("\ndata: "); printBuffer(packet->packet+SVC_PACKET_HEADER_LEN, packet->dataLen); fflush(stdout);
	*/
	
	if(PRINT_LOG)
		printf("[%d] encypt packet %d\n", getTime(), packet->getSequence());
			
	aesgcmMutex.lock();
	this->aesgcm->encrypt(iv, ivLen, packet->packet+SVC_PACKET_HEADER_LEN, packet->dataLen - SVC_PACKET_HEADER_LEN, packet->packet, SVC_PACKET_HEADER_LEN, &encrypted, &encryptedLen, &tag, &tagLen);
	aesgcmMutex.unlock();
	
	if(PRINT_LOG)
		printf("[%d] encypt packet %d done\n", getTime(), packet->getSequence());
	/*//printf("\ngot:");
	//printf("\nencrypted: "); printBuffer(encrypted, encryptedLen); fflush(stdout);
	//printf("\ntag: "); printBuffer(tag, tagLen); fflush(stdout);
	*/
	
	//-- set body to be encrypted
	packet->setBody(encrypted, encryptedLen);
	//-- copy tag and tagLen to the end of packet
	packet->pushCommandParam(tag, tagLen);	
	

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
	
		
	/*//printf("\ndecrypt packet with:");
	//printf("\niv: "); printBuffer(iv, ivLen); fflush(stdout);
	//printf("\naad: "); printBuffer(aad, aadLen); fflush(stdout);
	//printf("\ntag: "); printBuffer(tag, tagLen); fflush(stdout);
	//printf("\nencrypted: "); printBuffer(packet->packet+SVC_PACKET_HEADER_LEN, packet->dataLen); fflush(stdout);*/
	
	if(PRINT_LOG)
		printf("[%d] decrypt packet %d\n", getTime(), packet->getSequence());

	aesgcmMutex.lock();
	rs = this->aesgcm->decrypt(iv, ivLen, packet->packet+SVC_PACKET_HEADER_LEN, packet->dataLen - SVC_PACKET_HEADER_LEN - 2 - tagLen, aad, aadLen, tag, tagLen, &decrypted, &decryptedLen);
	aesgcmMutex.unlock();
	
	if(PRINT_LOG)
		printf("[%d] decrypt packet %d done\n", getTime(), packet->getSequence());
	/*//printf("\ngot:");
	//printf("\ndecrypted: "); printBuffer(decrypted, decryptedLen); fflush(stdout);*/
		
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
			SVCPacket* packet = new SVCPacket(buffer, readrs);
			_this->unixIncomingQueue.enqueue(packet);
			// if(PRINT_LOG)
			// 	printf("[%d] unix recv packet %d\n", getTime(), packet->getSequence());
			// _this->readPacketCounter++;
			//printf("\ndaemon endpoint unix reads packet:"); printBuffer(buffer, readrs); fflush(stdout);
		}
		/*else{
			//printf("\ndaemon endpoint unix reads fail, errno: %d", errno);
		}*/
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
			if(PRINT_LOG)
				printf("[%d] unix send packet %d\n", getTime(), packet->getSequence());
			if (sendrs == -1){
				printf("\ndaemon unix writes packet fail, errno: %d", errno); //111 or 107
			}

			delete packet;		
		}
	}
	pthread_exit(EXIT_SUCCESS);
}

void DaemonEndpoint::daemon_endpoint_inet_incoming_packet_handler(SVCPacket* packet, void* args){
	if(PRINT_LOG)
		printf("[%d] handle packet %d\n", getTime(), packet->getSequence());
	daemonEpHandledInPacketCounter++;
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
		decryptSuccessPackets++;
		// //send htp ack for encrypted packet
		// uint8_t* htp_ack_frame = new uint8_t[HTP_HEADER_LENGTH + packet->dataLen];
		// memcpy(htp_ack_frame + HTP_HEADER_LENGTH, packet->packet, packet->dataLen);
		// HtpPacket* htpPkt = new HtpPacket(htp_ack_frame, packet->dataLen + HTP_HEADER_LENGTH);
		// htpPkt->setSrcAddr(&packet->srcAddr, packet->srcAddrLen);
		// // print track log
		// // printf("send ack for encrypted %d\n", htpPkt->getSequence());
		// daemonHtpSocket->sendACK(htpPkt);

		// delete [] htp_ack_frame;
		// delete htpPkt;
		
		//printf("\ndaemon inet incoming: packet after decrypt: "); printBuffer(packet->packet, packet->dataLen); fflush(stdout);
		//-- check sequence and address to be update
		if (memcmp(&_this->remoteAddr, &packet->srcAddr, _this->remoteAddrLen)!=0){
			_this->connectToAddress((struct sockaddr_in*)&packet->srcAddr, packet->srcAddrLen);
		}
		
		if ((infoByte & SVC_COMMAND_FRAME) != 0x00){
			enum SVCCommand cmd = (enum SVCCommand)packet->packet[CMD_BYTE];
			switch (cmd){
				case SVC_CMD_SHUTDOWN_ENDPOINT:
					printf("\nother end of connection has shutdown"); fflush(stdout);
					delete packet;
					_this->daemonShutdownCall = true;
					_this->working = false;
					break;
					
				case SVC_CMD_CONNECT_OUTER2:
					if(PRINT_LOG)
						printf("receive SVC_CMD_CONNECT_OUTER2\n");
					pthread_mutex_lock(&_this->stateMutex);
					if (_this->state < SVC_CMD_CONNECT_OUTER2){		
						//-- pop encrypted proof					
						if (!packet->popCommandParam(param, &paramLen)){
							delete packet;
							pthread_mutex_unlock(&_this->stateMutex);
							break;
						}
						_this->encryptedProof = new SVCPacket(param, paramLen);
					
						if (!packet->popCommandParam(param, &paramLen)){
							delete _this->encryptedProof;
							delete packet;
							pthread_mutex_unlock(&_this->stateMutex);
							break;
						}
						_this->encryptedECPoint = new SVCPacket(param, paramLen);
		
						//-- change command to INNER_4				
						packet->switchCommand(SVC_CMD_CONNECT_INNER4);
						//-- app svc is still waiting for the 'old' endpointID, push the current endpointID as new param
						packet->pushCommandParam(packet->packet+1, ENDPOINTID_LENGTH);
						//-- clear the 6&7 byte of endpointID
						packet->packet[1+6]=0x00;
						packet->packet[1+7]=0x00;				
						_this->unixOutgoingQueue.enqueue(packet);

						if(PRINT_LOG)
							printf("send SVC_CMD_CONNECT_INNER4\n");

						_this->state = SVC_CMD_CONNECT_OUTER2;
						pthread_mutex_unlock(&_this->stateMutex);
					}
					else{
						delete packet;
						pthread_mutex_unlock(&_this->stateMutex);
					}
					break;
			
				case SVC_CMD_CONNECT_OUTER3:

					if(PRINT_LOG)
						printf("receive SVC_CMD_CONNECT_OUTER3\n");

					pthread_mutex_lock(&_this->stateMutex);
					if (_this->state < SVC_CMD_CONNECT_OUTER3){					
						packet->switchCommand(SVC_CMD_CONNECT_INNER8);

						if(PRINT_LOG)
							printf("send SVC_CMD_CONNECT_INNER8\n");

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
			if(PRINT_LOG)
				printf("[%d] forward packet %d\n", getTime(), packet->getSequence());
			_this->unixOutgoingQueue.enqueue(packet);
			forwardedToAppPacketCounter++;
		}
	}
	else{
		uint32_t seq = packet->getSequence();
		printf("\nfailed to decrypt packet %d", seq); fflush(stdout);
		// daemonHtpSocket->sendNACK(seq, (struct sockaddr *) &_this->remoteAddr, _this->remoteAddrLen);
		// DecryptLogfile->write((char*)&seq, 4);
		// DecryptLogfile->write((char*)packet->packet, packet->dataLen);
		// DecryptLogfile->write(gap, 10);
		// logPacket(DecryptLogfile, seq, packet->packet, packet->dataLen);

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
				//_this->inetOutgoingQueue.enqueue(packet);
				delete packet;
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

				if(PRINT_LOG)
					printf("receive SVC_CMD_CONNECT_INNER1\n");

				pthread_mutex_lock(&_this->stateMutex);
				if (_this->state < SVC_CMD_CONNECT_INNER1){				
					//-- extract remote address
					if (!packet->popCommandParam(param, &paramLen)){															
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
					if (!packet->popCommandParam(param, &paramLen)){
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
					packet->pushCommandParam(encrypted, encryptedLen);
					
					free(encrypted);
					delete aes256;
					delete ecpoint;
					
					//-- switch commandID
					packet->switchCommand(SVC_CMD_CONNECT_OUTER1);
					//-- send the packet to internet					
					_this->inetOutgoingQueue.enqueue(packet);

					if(PRINT_LOG)
						printf("send SVC_CMD_CONNECT_OUTER1\n");

					_this->state = SVC_CMD_CONNECT_INNER1;
					pthread_mutex_unlock(&_this->stateMutex);
				}
				else{
					delete packet;
					pthread_mutex_unlock(&_this->stateMutex);
				}				
				break;
			
			case SVC_CMD_CONNECT_INNER3:	
				if(PRINT_LOG)
					printf("receive SVC_CMD_CONNECT_INNER3\n");

				pthread_mutex_lock(&_this->stateMutex);
				if (_this->state < SVC_CMD_CONNECT_INNER3){

					//-- app responded with CONNECT_INNER3, now can connect to app socket
					_this->connectToAppSocket();
				
					if (!packet->popCommandParam(param, &paramLen)){
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
						if (!packet->popCommandParam(param, &paramLen)){
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
						if (!packet->popCommandParam(solutionProof, &solutionProofLen)){
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
						packet->switchCommand(SVC_CMD_CONNECT_OUTER2);
						//-- attach Ey(gy) to packet
						packet->pushCommandParam(encrypted, encryptedLen);					
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
						packet->pushCommandParam(param, paramLen);
						free(encrypted);
						free(tag);
						delete aes256;
						_this->state = SVC_CMD_CONNECT_INNER3;
						pthread_mutex_unlock(&_this->stateMutex);
						//-- send this packet to internet
						_this->inetOutgoingQueue.enqueue(packet);

						if(PRINT_LOG)
							printf("send SVC_CMD_CONNECT_OUTER2\n");
					}
					else{
						//-- decryted gx is damaged
						printf("2\n");
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
				
				if(PRINT_LOG)
					printf("receive SVC_CMD_CONNECT_INNER5\n");

				pthread_mutex_lock(&_this->stateMutex);
				if (_this->state < SVC_CMD_CONNECT_INNER5){
					requested_security_strength = _this->curve->getRequestSecurityLength();		
					if (!packet->popCommandParam(solution, &solutionLen)){
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
								packet->switchCommand(SVC_CMD_CONNECT_INNER6);
								packet->pushCommandParam(decrypted, decryptedLen);	
								_this->state = SVC_CMD_CONNECT_INNER5;											
								_this->unixOutgoingQueue.enqueue(packet);

								if(PRINT_LOG)
									printf("send SVC_CMD_CONNECT_INNER6\n");

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

				if(PRINT_LOG)				
					printf("receive SVC_CMD_CONNECT_INNER7\n");

				//-- authenticated
				pthread_mutex_lock(&_this->stateMutex);
				_this->state = SVC_CMD_CONNECT_INNER7;
				_this->isAuth = true;
				packet->switchCommand(SVC_CMD_CONNECT_OUTER3);
				packet->packet[INFO_BYTE] |= SVC_ENCRYPTED;
				_this->inetOutgoingQueue.enqueue(packet);

				if(PRINT_LOG)
					printf("send SVC_CMD_CONNECT_OUTER3\n");

				pthread_mutex_unlock(&_this->stateMutex);
				break;							
			
			case SVC_CMD_CONNECT_INNER9:

				if(PRINT_LOG)				
					printf("receive SVC_CMD_CONNECT_INNER9\n");

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
			//printf("\ndaemon_unix_reading_loop read a packet: "); printBuffer(buffer, readrs);
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

		#ifdef _USING_HTP_
			readrs = daemonHtpSocket->recvfrom(buffer, SVC_DEFAULT_BUFSIZ, 0, (struct sockaddr*)&srcAddr, &srcAddrLen);		
		#else
			readrs = recvfrom(daemonInSocket, buffer, SVC_DEFAULT_BUFSIZ, 0, (struct sockaddr*)&srcAddr, &srcAddrLen);		
		#endif

		if (readrs>0){
			//printf("\ndaemon_inet_reading_loop read a packet: "); printBuffer(buffer, readrs);
			packet = new SVCPacket(buffer, readrs);
			packet->setSrcAddr((struct sockaddr_storage*)&srcAddr, srcAddrLen);			
			if(PRINT_LOG) {
				printf("[%d] recv packet %d\n", getTime(), packet->getSequence());
				// printBuffer(packet->packet, packet->dataLen);
			}

			daemonInetIncomingQueue.enqueue(packet);
			readPacketCounter++;
			//printf("."); fflush(stdout);
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
		// shutdown(daemonInSocket, SHUT_RD);
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

void daemon_unix_incoming_packet_handler(SVCPacket* packet, void* args){
	uint8_t infoByte = packet->packet[INFO_BYTE];
	if ((infoByte & SVC_COMMAND_FRAME) != 0x00){
		enum SVCCommand cmd = (enum SVCCommand)packet->packet[CMD_BYTE];
		uint64_t endpointID = *((uint64_t*)(packet->packet+1));
		bool existed = false;
		switch (cmd){
			case SVC_CMD_CREATE_ENDPOINT:
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
				if (existed){
					delete packet;
				}
				else{
					DaemonEndpoint* endpoint;
					try{
						endpoint = new DaemonEndpoint(endpointID);
						endpoint->isInitiator = true;
						if (endpoint->connectToAppSocket()==0){
							endpoints[endpointID] = endpoint;
							//-- send back the packet
							endpoint->unixOutgoingQueue.enqueue(packet);
							//-- add this endpoint to collection
							endpoints[endpointID] = endpoint;
						}
						else{
							delete packet;
							delete endpoint;
						}
					}
					catch(const char* err){
						delete packet;
					}
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

void daemon_inet_incoming_packet_handler(SVCPacket* packet, void* args){
	handledPacketCounter++;
	static uint8_t param[SVC_DEFAULT_BUFSIZ] = "";
	static uint16_t paramLen;
	
	if (packet->dataLen>SVC_PACKET_HEADER_LEN){
		uint8_t infoByte = packet->packet[INFO_BYTE];
		uint64_t endpointID = *((uint64_t*)(packet->packet+1));
	
		if ((infoByte & SVC_COMMAND_FRAME) != 0x00){
			if ((infoByte & SVC_ENCRYPTED)!=0x00){
				if (endpoints[endpointID] != NULL && endpoints[endpointID]->working){
					//-- forward packet if endpoint found
					//printf("\nforwarding encrypted command packet (OUTER3)"); fflush(stdout);
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

						if(PRINT_LOG)
							printf("receive SVC_CMD_CONNECT_OUTER1\n");

						//-- extract DH-1
						if (!packet->popCommandParam(param, &paramLen)){
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
						if (!packet->popCommandParam(param, &paramLen)){
							delete packet;
							dmnEndpoint->working = false;
							break;
						}
						appID = *((uint32_t*)param);					
						
						//-- send the packet to the corresponding app
						packet->switchCommand(SVC_CMD_CONNECT_INNER2);					
						appSockPath = string(SVC_CLIENT_PATH_PREFIX) + to_string(appID);
						appSockAddr.sun_path[0] = '\0';
						memcpy(appSockAddr.sun_path+1, appSockPath.c_str(), appSockPath.size());
						//-- replace the oldEndpointID by the newEndpointID
						memcpy(packet->packet+1, (uint8_t*)&newEndpointID, ENDPOINTID_LENGTH);
						sendrs = sendto(daemonUnSocket, packet->packet, packet->dataLen, 0, (struct sockaddr*)&appSockAddr, sizeof(appSockAddr));

						if(PRINT_LOG)
							printf("send SVC_CMD_CONNECT_INNER2\n");

						delete packet;
						break;
			
					case SVC_CMD_CONNECT_OUTER2:

						if(PRINT_LOG)
							printf("receive SVC_CMD_CONNECT_OUTER2\n");

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

void showHelp(){
	//printf("\nsvc-daemon: daemon process for svc-based applications");
	//printf("\nusage:");
	//printf("\n\t--default-config config_file");
	//printf("\n\t\tGenerate svc-daemon's default configuration and save it to config_file\n");
	//printf("\n\t--help");
	//printf("\n\t\tShow this help content\n");
	//printf("\n\t--start -c config_file");
	//printf("\n\t\tStart a new instance of svc-daemon using the configuration inside config_file\n");
	//printf("\n\t--start -i image_file");
	//printf("\n\t\tStart the svc-daemon using the previously saved infomation in image_file\n");
	//printf("\n\t--stop [-i image_file]");
	//printf("\n\t\tGracefully stop the running svc-daemon instance and (optionally) save \n\t\tall current endpoints' states to image_file. This is generally used \n\t\tin svc update/maintenance\n");
	//printf("\n");
	fflush(stdout);
}

int startDaemonWithConfig(const char* configFile){
	const char* errorString;
	
	working = true;	
	//-- block all signals, except SIGINT
    sigset_t blockSignals;
    sigfillset(&blockSignals);
    sigdelset(&blockSignals, SIGINT);    
    pthread_sigmask(SIG_SETMASK, &blockSignals, NULL);

	pthread_attr_t attr;
	pthread_attr_init(&attr);
	
	//-- create a daemon unix socket and bind
	daemonUnSocket = socket(AF_LOCAL, SOCK_DGRAM, 0);
	memset(&daemonSockUnAddress, 0, sizeof(daemonSockUnAddress));
	daemonSockUnAddress.sun_family = AF_LOCAL;
	daemonSockUnAddress.sun_path[0]='\0';
	memcpy(daemonSockUnAddress.sun_path+1, SVC_DAEMON_PATH.c_str(), SVC_DAEMON_PATH.size());			
	if (bind(daemonUnSocket, (struct sockaddr*) &daemonSockUnAddress, sizeof(daemonSockUnAddress)) == -1) {		
		errorString = SVC_ERROR_BINDING;
        goto error1;
    }
    //-- then create a reading thread
	if (pthread_create(&daemonUnixReadingThread, &attr, daemon_unix_reading_loop, NULL) != 0){
		errorString = SVC_ERROR_CRITICAL;
		goto error2;
	}
    
    //--TODO:	TO BE CHANGED TO HTP
    

	#ifdef _USING_HTP_	
		//--	create htp socket and bind to localhost
		try {
			daemonHtpSocket = new HtpSocket(SVC_DAEPORT);
		}
		catch(...) {
			working = false;
	    	pthread_join(daemonUnixReadingThread, NULL);
	    	errorString = SVC_ERROR_BINDING;
	    	goto error2;
		}
	#else
	    daemonInSocket = socket(AF_INET, SOCK_DGRAM, 0);
	    memset(&daemonSockInAddress, 0, sizeof(daemonSockInAddress));
	    daemonSockInAddress.sin_family = AF_INET;
	    daemonSockInAddress.sin_port = htons(SVC_DAEPORT);
		daemonSockInAddress.sin_addr.s_addr = htonl(INADDR_ANY);      
	    if (bind(daemonInSocket, (struct sockaddr*) &daemonSockInAddress, sizeof(daemonSockInAddress))){    	
	    	working = false;
	    	pthread_join(daemonUnixReadingThread, NULL);
	    	errorString = SVC_ERROR_BINDING;
	    	goto error2;
	    }
	#endif

    //-- then create a reading thread
	if (pthread_create(&daemonInetReadingThread, &attr, daemon_inet_reading_loop, NULL) != 0){		
		working = false;
    	pthread_join(daemonUnixReadingThread, NULL);
    	errorString = SVC_ERROR_CRITICAL;
		goto error3;
	}
    
    //-- handle SIGINT
	struct sigaction act;
	act.sa_flags = 0;
	act.sa_handler = signal_handler;
	sigfillset(&act.sa_mask);
	sigdelset(&act.sa_mask, SIGINT);
	sigaction(SIGINT, &act, NULL);
	
	//-- packet handler
	try{
    	daemonUnixIncomingPacketHandler = new PacketHandler(&daemonUnixIncomingQueue, daemon_unix_incoming_packet_handler, NULL);
   		daemonInetIncomingPacketHandler = new PacketHandler(&daemonInetIncomingQueue, daemon_inet_incoming_packet_handler, NULL);
		endpointChecker = new PeriodicWorker(1000, checkEndpointLiveTime, NULL);
		goto initSuccess;
	}
	catch(...){
		working = false;
		pthread_join(daemonUnixReadingThread, NULL);
		pthread_join(daemonInetReadingThread, NULL);
		errorString = SVC_ERROR_CRITICAL;
		goto error3;
	}    
    
    error3:

    	#ifdef _USING_HTP_
    		daemonHtpSocket->close();
    	#else
    		close(daemonInSocket);
    	#endif
    		
    error2:
    	close(daemonUnSocket);
    error1:
    	//printf("\nError: %s\n", errorString);
    	return EXIT_FAILURE;
    	
    initSuccess:
		//--	POST-SUCCESS JOBS	--//		
		endpoints.clear();
    	printf("\nSVC daemon is running\n"); fflush(stdout);
    	        	
        daemonUnixIncomingPacketHandler->waitStop();
        daemonInetIncomingPacketHandler->waitStop();
    	endpointChecker->waitStop();
        	
    	delete daemonUnixIncomingPacketHandler;
    	delete daemonInetIncomingPacketHandler;
    	delete endpointChecker;
    	printf("\nSVC daemon stopped\n");
    	return EXIT_SUCCESS;
}


int startDaemonWithImage(const char* imageFile){
}

void generateDefaultConfig(const char* configFile){
}


int main(int argc, char** argv){
	
	const char* errorString;
	
	if (argc == 1){
		//-- cal program without any argument. show help
		showHelp();		
	}
	else{	
		return startDaemonWithConfig(NULL);
		
	}
}


