#ifndef __SVC_NAMEDPIPE__
#define __SVC_NAMEDPIPE__

    #include <string>
    #include <cstdio>

    #include "utils.h"
    #include "../crypto/crypto-utils.h"

    #ifdef _WIN32
    #else
        #include <sys/un.h>
        #include <sys/socket.h>
    #endif


    enum class NamedPipeMode{
        NP_READ,
        NP_WRITE
    };

    using namespace utils;

    class NamedPipe{

        NamedPipeMode mode;

        bool isOpen;

        #ifdef _WIN32
        
        #else
            std::string socketFilePath;
            struct sockaddr_un unixDomainSocketAddr;
            int unixDomainSocket;
        #endif

        public:
            
            NamedPipe(const std::string& fileName, NamedPipeMode mode){
                this->mode = mode;
                #ifdef _WIN32
                #else
                    this->socketFilePath = utils::getOSTempDirectory(true) + fileName;
                    switch (this->mode){
                        case NamedPipeMode::NP_READ:
                                unixDomainSocket = socket(AF_LOCAL, SOCK_DGRAM, 0);
                                memset(&unixDomainSocketAddr, 0, sizeof(unixDomainSocketAddr));
                                unixDomainSocketAddr.sun_family = AF_LOCAL;
                                #ifdef __linux__
                                    unixDomainSocketAddr.sun_path[0]='\0';
                                    memcpy(unixDomainSocketAddr.sun_path+1, socketFilePath.c_str(), socketFilePath.size());
                                #else
                                    memcpy(unixDomainSocketAddr.sun_path, socketFilePath.c_str(), socketFilePath.size());
                                #endif
                                if (::bind(unixDomainSocket, (struct sockaddr*) &unixDomainSocketAddr, sizeof(unixDomainSocketAddr)) != 0) {
                                    throw ERR_CONNECT_SOCKET;
                                }
                            break;
                        case NamedPipeMode::NP_WRITE:
                                unixDomainSocket = socket(AF_LOCAL, SOCK_DGRAM, 0);
                                memset(&unixDomainSocketAddr, 0, sizeof(unixDomainSocketAddr));
                                unixDomainSocketAddr.sun_family = AF_LOCAL;
                                #ifdef __linux__
                                    unixDomainSocketAddr.sun_path[0]='\0';
                                    memcpy(unixDomainSocketAddr.sun_path+1, socketFilePath.c_str(), socketFilePath.size());
                                #else
                                    memcpy(unixDomainSocketAddr.sun_path, socketFilePath.c_str(), socketFilePath.size());
                                #endif		
                                if (::connect(unixDomainSocket, (struct sockaddr*) &unixDomainSocketAddr, sizeof(unixDomainSocketAddr)) != 0) {
                                    throw ERR_CONNECT_SOCKET;
                                }
                            break;
                        default:
                            throw ERR_NOT_SUPPORTED;
                            break;
                    }
                #endif
                this->isOpen = true;
            }

            ssize_t read(uint8_t* buffer, uint32_t bufferLen){
                #ifdef _WIN32
                #else
                    return ::read(this->unixDomainSocket, buffer, bufferLen);
                #endif
            }

            ssize_t write(const uint8_t* buffer, uint32_t bufferLen){
                return ::write(this->unixDomainSocket, buffer, bufferLen);
            }

            void close(){
                #ifdef _WIN32
                #else
                    ::close(this->unixDomainSocket);
                #endif
                this->isOpen = false;
            }

            ~NamedPipe(){
                #ifdef _WIN32
                #else
                    if (this->isOpen){
                        ::close(this->unixDomainSocket);
                    }
                    #ifndef __linux__
                        //-- we use virtual unix domain socket on linux so do not need to unlink
                        if (this->mode == NamedPipeMode::NP_READ){
                            ::unlink(this->socketFilePath.c_str());
                        }
                    #endif
                #endif
            }
    };

#endif
