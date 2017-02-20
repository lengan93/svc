#include "HTP.h"

HtpSocket::HtpSocket() {
	UDPSocket = socket(AF_INET, SOCK_DGRAM, 0);
}

HtpSocket::HtpSocket(in_port_t localPort) throw(){
	UDPSocket = socket(AF_INET, SOCK_DGRAM, 0);

	struct sockaddr_in localAddress = {0};
    localAddress.sin_family = AF_INET;
    localAddress.sin_port = htons(localPort);
	localAddress.sin_addr.s_addr = htonl(INADDR_ANY); 
	if( this->bind((struct sockaddr*) &localAddress, sizeof(localAddress)) ) {
		throw;
	}
}

HtpSocket::HtpSocket(size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {

}

int HtpSocket::bind(struct sockaddr *my_addr, socklen_t addrlen) {
	return ::bind(UDPSocket, my_addr, addrlen);
}

int HtpSocket::close() {
	return ::close(UDPSocket);
}

int HtpSocket::sendto(const void *msg, size_t len, int flags, const struct sockaddr *to, socklen_t tolen) {
	return ::sendto(UDPSocket, msg, len, flags, to, tolen);
}

int HtpSocket::recvfrom(void *buf, int len, unsigned int flags, struct sockaddr *from, socklen_t *fromlen) {
	return ::recvfrom(UDPSocket, buf, len, flags, from, fromlen);
}

HtpSocket::~HtpSocket() {
	this->close();
}