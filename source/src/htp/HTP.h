/*
	THIS HEADER AND ITS SOURCE FILE DEFINE AND IMPLEMENT THE 'HYBRID TRANSMISSION PROTOCOL' (HTP) IN 
	APPLICATION LAYER. THIS IMPLEMENTATION IS A WRAPPER OF INET UDP PROTOCOL, ADDING EXTRA FUNCTIONALITIES
	AND FEATURES.
	
	AUTHOR: IMMORT (univers.immort@gmail.com)
*/

#ifndef __TOM_HTP__
#define __TOM_HTP__

	#include <sys/types.h>          //--	Portability for BDS socket	
	#include <sys/socket.h>
	#include <unistd.h>				//--	For 'close', 'shutdown'
	
	#include "../utils/MutexedQueue.h"
	#include "HtpDataQueue.h"
	
	#define DEFAULT_MTP					65536
	
	#define HTP_SOCKET_NOLOST			0
	#define HTP_SOCKET_LOST_TOLERATE	1
	#define HTP_SOCKET_URGENT_PRIORITY	2
	#define HTP_SOCKET_HIGH_PRIORITY	3
	#define HTP_SOCKET_NORMAL_PRIORITY	4
	#define HTP_SOCKET_LOW_PRIORITY		5
	
	class HtpSocket{
	
		class HtpPacket{
			
		};
		
		class HtpConnection{
			public:
				struct sockaddr_storage remoteAddr;
				socklen_t remoteAddrLen;
				uint32_t sentID;
				uint32_t expectedID;
				
				HtpDataQueue* dataOutQueue;
				HtpDataQueue* dataInQueue;
				
				uint32_t waitingPacketID;
				uint32_t sendingPacketID;				
			
				HtpConnection(const struct sockaddr* addr, socklen_t addrlen){
					this->sentID = 0;
					this->expectedID = 0;
					this->remoteAddrLen = addrlen;
					memset(&this->remoteAddr, addr, addrlen);
				}
			
				void changeRemoteAddress(const struct sockaddr* addr, socklen_t addrlen){
					this->remoteAddrLen = addrlen;
					memset(&this->remoteAddr, addr, addrlen);
				}
			
				bool recvPacket(uint8_t* data, ssize_t dataLen){
					uint32_t packetID = *((uint32_t*)(data+2));
					
				}
				
				ssize_t sendPacket(uint8_t* data, ssize_t dataLen);
		};
	
		private:
					 
			static void* htp_reading_loop(void* args);
			
			//-- messsage queues
			MutexedQueue<HtpPacket*>* urgReading;
			MutexedQueue<HtpPacket*>* higReading;
			MutexedQueue<HtpPacket*>* norReading;
			MutexedQueue<HtpPacket*>* lowReading;
			
			
			MutexedQueue<HtpPacket*>* urgWriting;
			MutexedQueue<HtpPacket*>* higWriting;
			MutexedQueue<HtpPacket*>* norWriting;
			MutexedQueue<HtpPacket*>* lowWriting;
			
			//-- member variable
			volatile bool working;
			bool bindSuccess;
			int udpSocket;
			unordered_map<string, HtpConnection*> connections;
			
			//-- reading & writing thread
			pthread_t readingThread;
			pthread_t writingThread;			
			
		public:
			HtpSocket();
			~HtpSocket();
						
			//-- wrapper
			static int bind(HtpSocket* sock, const struct sockaddr* addr, socklen_t addrlen);
			static int shutdown(HtpSocket* sock, int how);
			static int close(HtpSocket* sock);			
			static ssize_t recvfrom(HtpSocket* sock, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen);
			static ssize_t sendto(HtpSocket* sock, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen);
			static int connect(HtpSocket* sock, const struct sockaddr* addr, socklen_t addrlen);
			static int setsockopt(HtpSocket* sock, int level, int optname, const void* optval, socklen_t optlen);
			
			//-- extra functionalities
			static int disconnect(HtpSocket* sock, const struct sockaddr* addr, socklen_t addrlen);
			static int reconnect(HtpSocket* sock, const struct sockaddr* old_addr, socklen_t old_addrlen, const struct sockaddr* new_addr, socklen_t new_addrlen);
	};

#endif




