#ifndef __TRANSPORT__
#define __TRANSPORT__

#include "../host/SVCHostIP.h"

class TransportHandler
{
public:
	virtual int sendData(uint8_t* data, uint32_t len) = 0;
	virtual int recvData(uint8_t* data, uint32_t* len) = 0;
	
	virtual int connect_to(SVCHost* host) = 0;
	virtual int listen(int port) = 0;
};

#endif