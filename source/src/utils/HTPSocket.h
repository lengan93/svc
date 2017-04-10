#ifndef __HTP_SOCKET__
#define __HTP_SOCKET__

    //-- TODO: this implement is only a simple wrapper of UDP protocol and needs to be changed
    #ifdef _WIN32
        //-- TODO: using winsock
    #else
        #include <sys/socket.h>
        #include <sys/types.h>
    #endif

    #include <cstring>
    #include "DataEndpoint.h"
    #include "HostAddr.h"

    class SocketAddr : public DataEndpointAddr{
        public:
            virtual ~SocketAddr(){}
    };

    class HTPSocket : public DataEndpoint{
        private:
            uint8_t networkType;

            int socket;

        public:
            HTPSocket(uint8_t networkType, uint8_t option){
                this->networkType = networkType;

                switch (networkType){
                    case NETWORK_TYPE_IPv4:
                        {    
                            this->socket = ::socket(AF_INET, SOCK_DGRAM, 0);
                        }
                        break;

                    case NETWORK_TYPE_SATURN:
                        {
                            //-- TODO: do something else
                        }
                        break;
                }
            }

            int bind(HostAddr* hostAddr){
                if (this->networkType == hostAddr->networkType){
                    int bindResult;
                    switch (networkType){
                        case NETWORK_TYPE_IPv4:
                            {         
                                struct sockaddr_in sa;
                                memcpy(&sa, hostAddr->networkAddr, sizeof(sa));
                                bindResult = ::bind(socket, (const struct sockaddr*)&sa, sizeof(sa));
                            }
                            break;

                        case NETWORK_TYPE_SATURN:
                            {
                                //-- TODO: do something else
                            }
                            break;
                    }
                    delete hostAddr;
                    return bindResult;
                }
                delete hostAddr;
                return -1;
            }

            int connect(const HostAddr* hostAddr){
                if (this->networkType == hostAddr->networkType){
                    int connectResult;
                    switch (networkType){
                        case NETWORK_TYPE_IPv4:
                            {
                                struct sockaddr_in sa;
                                memcpy(&sa, hostAddr->networkAddr, sizeof(sa));
                                connectResult = ::bind(socket, (const struct sockaddr*)&sa, sizeof(sa));
                            }
                            break;

                        case NETWORK_TYPE_SATURN:
                            {
                                //-- TODO: do something else
                            }
                            break;
                    }
                    return connectResult;
                }
                return -1;
            }

            ssize_t read(uint8_t* buffer, uint16_t bufferLen, uint8_t option){
                //-- TODO: option should be processed
                return ::recv(this->socket, buffer, bufferLen, 0);
            }

            ssize_t write(const uint8_t* buffer, uint16_t bufferLen, uint8_t option){
                //-- TODO: option should be processed
                return ::send(this->socket, buffer, bufferLen, 0);;
            }

            ssize_t readFrom(DataEndpointAddr** addr, uint8_t* buffer, uint16_t bufferLen, uint8_t option){
                ssize_t readResult;
                switch (networkType){
                    case NETWORK_TYPE_IPv4:
                        {
                            struct sockaddr_in sa;
                            socklen_t sockLen = 0;
                            readResult = recvfrom(this->socket, buffer, bufferLen, 0, (struct sockaddr*)&sa, &sockLen);
                            if (readResult >= 0){
                                HostAddr* hostAddr = new HostAddr();
                                hostAddr->networkType = networkType;
                                memcpy(hostAddr->networkAddr, &sa, sizeof(sa));
                                *addr = hostAddr;
                            }
                        }
                        break;

                    case NETWORK_TYPE_SATURN:
                        {
                            //-- TODO: do something else
                            readResult = -1;
                        }
                        break;
                }
                return readResult;
            }

            ssize_t writeTo(const DataEndpointAddr* addr, const uint8_t* buffer, uint16_t bufferLen, uint8_t option){
                //-- TODO: option should be processed

                //-- convert addr to correct network type format
                HostAddr* hostAddr = (HostAddr*)addr;
                switch (networkType){
                    case NETWORK_TYPE_IPv4:
                        {
                            struct sockaddr_in sa;
                            memcpy(&sa, hostAddr->networkAddr, sizeof(sa));
                            return ::sendto(this->socket, buffer, bufferLen, 0, (const struct sockaddr*) &sa, sizeof(sa));
                        }
                        break;

                    case NETWORK_TYPE_SATURN:
                        {
                            //-- TODO: do something else
                            return -1;
                        }
                        break;

                    default:
                        {
                            return -1;
                        }
                }
            }

            void close(){
                ::close(this->socket);
            }

            ~HTPSocket(){
                ::close(this->socket);
            }
    };

#endif