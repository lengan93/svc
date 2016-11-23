/*
	THIS HEADER AND ITS SOURCE FILE DEFINE AND IMPLEMENT THE 'HYBRID TRANSMISSION PROTOCOL' (HTP) IN 
	APPLICATION LAYER. THIS IMPLEMENTATION IS A WRAPPER OF INET UDP PROTOCOL, ADDING EXTRA FUNCTIONALITIES
	AND FEATURES.
	
	AUTHOR: IMMORT (univers.immort@gmail.com)
*/

#ifndef __TOM_HTP__
#define __TOM_HTP__

	class HtpSocket(){
		
		
			~HtpSocket();
			
			static ssize_t sendto(/*int sockfd*/ HtpSocket* socket, const void *buf
		public:
			HtpSocket();, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
			
	};

#endif
