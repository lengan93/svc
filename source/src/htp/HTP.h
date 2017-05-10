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
	public:
		int sendCounter = 0;
		int recvCounter = 0;

		int successReceivedPackets = 0;
		int resendPackets = 0;

		HtpSocket() throw();

		HtpSocket(in_port_t localPort) throw();

		// HtpSocket(size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
		
		int bind(struct sockaddr *my_addr, socklen_t addrlen);

		int close();

		int sendto(const void *msg, size_t len, int flags, const struct sockaddr *to, socklen_t tolen);

		int recvfrom(void *buf, int len, unsigned int flags, struct sockaddr *from, socklen_t *fromlen);

		void sendACK(HtpPacket* packet);
		
		void sendNACK(uint32_t seq, const struct sockaddr *to, socklen_t tolen);
		
		~HtpSocket();

	private:

		int UDPSocket;	
		
		// static ssize_t sendto(/*int sockfd*/ HtpSocket* socket, const void *buf);

		// mutex waitingACKListMutex;
		// mutex outGoingSetMutex;
		mutex inComingBufferMutex;
		mutex sendMutex;

		// MutexedQueue<HtpPacket*> waitingACKPacketQueue;		//buffer of sent packets, used in case resend a lost packet
		
		//buffer of sent packets, used in case resend a lost packet
		MutexedQueue<HtpPacket*>					waitingACKPacketList;		

		//buffer of received ACK messages
		MutexedQueue<HtpPacket*> 					receivedACKQueue;		

		//buffer of lost packets (presented by sequence number)
		set<uint32_t> 								missingPackets;	

		// set<HtpPacket*, HtpPacketComparator> 		outGoingPackets;

		MutexedQueue<HtpPacket*> 					inComingQueue;
		set<HtpPacket*, HtpPacketComparator> 		reordedPackets;
		// set<HtpPacket*, HtpPacketComparator> 		inComingQueue;

		int sendPacket(HtpPacket* packet);

		pthread_t htp_reading_thread;
		pthread_t htp_writing_thread;
		pthread_t htp_ack_handle_thread;
		pthread_t htp_retransmission_thread;

		static void* htp_retransmission_loop(void* args);
		static void* htp_ack_handler(void* args);
		static void* htp_reading_loop(void* args);
		static void* htp_writing_loop(void* args);
		static void htp_retransmission_timeout_handler(void* args);

		bool checkSequence(uint32_t seq);

		uint32_t biggestSeq = 0; //the biggest sequence number received
		uint32_t currentSeq = 1;
		uint32_t receiverWindowLeftSideSeq = 1;
};

#endif
