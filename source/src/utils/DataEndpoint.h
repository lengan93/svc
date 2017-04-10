#ifndef __DATA_ENDPOINT__
#define __DATA_ENDPOINT__

    #include <cstdio>

	#include "DataEndpointAddr.h"
    
    class DataEndpoint{
        public:
            virtual ssize_t read(uint8_t* buffer, uint16_t bufferLen, uint8_t option){return 0;}
            virtual ssize_t write(const uint8_t* buffer, uint16_t bufferLen, uint8_t option){return 0;}
            virtual ssize_t readFrom(DataEndpointAddr** addr, uint8_t* buffer, uint16_t bufferLen, uint8_t option){return 0;}
            virtual ssize_t writeTo(const DataEndpointAddr* addr, const uint8_t* buffer, uint16_t bufferLen, uint8_t option){return 0;}
            virtual ~DataEndpoint(){}
    };

#endif