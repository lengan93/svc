#include "HTP.h"

int HtpSocket::bind(HtpSocket* sock, const struct sockaddr* addr, socklen_t addrlen){
	int retval;
	sock->udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
	//-- call (global) socket bind, not the member function (otherwise it will create a recursive call)
	retval = ::bind(sock->udpSocket, addr, addrlen);
	if (retval == 0){
		//-- start reading thread		
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		retval = pthread_create(&this->readingThread, &attr, htp_reading_loop, this);
	}
	return retval;
}

int HtpSocket::shutdown(HtpSocket* sock, int how){
	return ::shutdown(sock->udpSocket, how);
}

int HtpSocket::close(HtpSocket* sock){
	sock->working = false;
	pthread_join(sock->readingThread, NULL);
	return ::close(sock->udpSocket);
}
			
ssize_t HtpSocket::recvfrom(HtpSocket* sock, void *buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen){
	static int i = 0;
	HtpPacket* packet;
	MutexedQueue<HtpPacket*>* queue;
	ssize_t retval;
	
	do{		
		if (i%2 == 0){
			queue = sock->urgReading;
		}
		else if ((i%14)%4 == 1){
			queue = sock->higReading;
		}
		else if ((i%14)%8 == 3){
			queue = sock->norReading;
		}
		else{
			queue = sock->lowReading;
		}
		i++;
		//-- read from the queue
		if (queue->peak(&packet)){
			*addrlen = packet->srcAddrLen;
			memcpy(src_addr, packet->srcAddr, packet->srcAddrLen);
			if (len>packet->dataLen)
				memcpy(buf, packet->packet, packet->dataLen);
				retval = packet->dataLen;
			}
			else{
				memcpy(buf, packet->packet, len);
				retval = len;
			}
			queue->dequeue();
			delete packet;
			return retval;
		}
	}
	while (working);
}

ssize_t HtpSocket::sendto(HtpSocket* sock, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen){
	string connectionID = string((char*)dest_addr, addrlen);
	if (sock->connections[connectionID]==NULL){
		return -1;
	}
	else{		
		return sock->connections[connectionID]->sendPacket(buf, len);
	}
}

int HtpSocket::connect(HtpSocket* sock, const struct sockaddr* addr, socklen_t addrlen){
	string connectionID = string((char*)addr, addrlen);
	if (sock->connections[connectionID]!=NULL){
		return -1;
	}
	else{
		HtpConnection* connection = new HtpConnection(addr, addrlen);
		sock->connections[connectionID] = connection;
		return 0;
	}
}


int HtpSocket::setsockopt(HtpSocket* sock, int level, int optname, const void *optval, socklen_t optlen){
}

int HtpSocket::disconnect(HtpSocket* sock, const struct sockaddr* addr, socklen_t addrlen){
	string connectionID = string((char*)addr, addrlen);
	if (sock->connections[connectionID]!=NULL){
		delete sock->connections[connectionID];
		sock->connections[connectionID] = NULL;
		return 0;
	}
	else{
		return -1;
	}
}

int HtpSocket::reconnect(HtpSocket* sock, const struct sockaddr* old_addr, socklen_t old_addrlen, const struct sockaddr* new_addr, socklen_t new_addrlen){
	string connectionID = string((char*)old_addr, old_addrlen);
	if (sock->connections[connectionID]!=NULL){
		sock->connections[connectionID]->changeRemoteAddress(new_addr, new_addrlen);		
		return 0;
	}
	else{
		return -1;
	}
}

void* HtpSocket::htp_reading_loop(void* args){
	HtpSocket* _this  = (HtpSocket*)args;
	uint8_t* buffer = (uint8_t*)malloc(DEFAULT_MTP);
	struct sockaddr_storage srcAddr;
	socklen_t srcAddrLen;
	string connectionID;
	HtpConnection* conn;
	ssize_t readrs;
	bool enqueuers;
	
	while (_this->working){		
		srcAddrLen = sizeof(srcAddr);
		readrs = ::recvfrom(_this->udpSocket, buffer, DEFAULT_MTP, 0, (struct sockaddr*) &srcAddr, &srcAddrLen);
		//-- interpret this
		if (readrs>0){
			connectionID = string((char*)srcAddr, srcAddrLen);
			conn = _this->connections[connectionID];
			if (conn==NULL){
				//-- no connection with this host, create new
				conn = new HtpConnection(srcAddr, srcAddrLen);
				_this->connections[connectionID] = conn;
			}
			enqueuers = conn->enqueuePacket(buffer, readrs);
			if ((buffer[0] & HTP_NOLOST) && enqueuers){
				//-- TODO: send back as ACK, remove data
				buffer[0] ^= HTP_NOLOST; //-- toggle NOLOST
				buffer[0] |= HTP_ACK;    //-- set ACK
			}
		}
	}
}

HtpSocket::HtpSocket(){
	this->working = true;	
}

HtpSocket::~HtpSocket(){
}


