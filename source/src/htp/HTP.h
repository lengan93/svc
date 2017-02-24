/*
	THIS HEADER AND ITS SOURCE FILE DEFINE AND IMPLEMENT THE 'HYBRID TRANSMISSION PROTOCOL' (HTP) IN 
	APPLICATION LAYER. THIS IMPLEMENTATION IS A WRAPPER OF INET UDP PROTOCOL, ADDING EXTRA FUNCTIONALITIES
	AND FEATURES.
	
	AUTHOR: IMMORT (univers.immort@gmail.com)
*/

#ifndef __TOM_HTP__
#define __TOM_HTP__

#include <unistd.h>
#include <netinet/in.h>

#include "../utils/MutexedQueue.h"
#include "Htp-header.h"
#include "HtpPacket.h"


class HtpSocket {
	
	private:

		int UDPSocket;
	
		~HtpSocket();
		
		// static ssize_t sendto(/*int sockfd*/ HtpSocket* socket, const void *buf);

		MutexedQueue<HtpPacket*> sentQueue;		//buffer of sent packets, used in case resend a lost packet
		MutexedQueue<HtpPacket*> waitingQueue;	//buffer of packets waiting for a lost packet

		MutexedQueue<HtpPacket*> outGoingQueue;
		MutexedQueue<HtpPacket*> inComingQueue;

		pthread_t htp_reading_thread;
		pthread_t htp_writing_thread;

		static void* htp_reading_loop(void* args);
		static void* htp_writing_loop(void* args);

		uint32_t currentSeq;							//Sequence counter

	public:

		HtpSocket() throw();

		HtpSocket(in_port_t localPort) throw();

		HtpSocket(size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
		
		int bind(struct sockaddr *my_addr, socklen_t addrlen);

		int close();

		int sendto(const void *msg, size_t len, int flags, const struct sockaddr *to, socklen_t tolen);

		int recvfrom(void *buf, int len, unsigned int flags, struct sockaddr *from, socklen_t *fromlen);

};

#endif
