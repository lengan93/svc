/*
	THIS HEADER AND ITS SOURCE FILE DEFINE AND IMPLEMENT THE 'HYBRID TRANSMISSION PROTOCOL' (HTP) IN 
	APPLICATION LAYER. THIS IMPLEMENTATION IS A WRAPPER OF INET UDP PROTOCOL, ADDING EXTRA FUNCTIONALITIES
	AND FEATURES.
	
	AUTHOR: IMMORT (univers.immort@gmail.com)
*/

#ifndef __TOM_HTP__
#define __TOM_HTP__

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>

class HtpSocket {
	
	private:

		int UDPSocket;
	
		~HtpSocket();
		
		static ssize_t sendto(/*int sockfd*/ HtpSocket* socket, const void *buf);

	public:

		HtpSocket();

		HtpSocket(in_port_t localPort) throw();

		HtpSocket(size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
		
		int bind(struct sockaddr *my_addr, socklen_t addrlen);

		int close();

		int sendto(const void *msg, size_t len, int flags, const struct sockaddr *to, socklen_t tolen);

		int recvfrom(void *buf, int len, unsigned int flags, struct sockaddr *from, socklen_t *fromlen);

};

#endif
