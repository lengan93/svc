#ifndef __HOST_ADDR__
#define __HOST_ADDR__
	
	#include <netinet/in.h>
	#include <arpa/inet.h>
#include <iostream>

	#include "DataEndpointAddr.h"

	class HostAddr : public DataEndpointAddr{
		public:
			uint8_t networkType;
			uint8_t networkAddr[20];

			HostAddr(){
				memset(this->networkAddr, 0, 20);
			}

			HostAddr(uint8_t networkType, std::string& networkAddr){
				this->networkType = networkType;
				memset(this->networkAddr, 0, 20);
				switch (networkType){
					case NETWORK_TYPE_IPv4:
						{
							//-- networkAddr must have format: a.b.c.d:port
							struct sockaddr_in sa;
							std::string ip = networkAddr.substr(0, networkAddr.find(":"));
							std::string port = networkAddr.substr(networkAddr.find(":")+1);
							printf("host addr created: ip=%s, port=%s\n", ip.c_str(), port.c_str());
							inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr));
							sa.sin_port = htons(std::stoi(port));

							//-- copy
							memcpy(this->networkAddr, &sa, sizeof(sa));
						}
						break;

					case NETWORK_TYPE_SATURN:
						{

						}
						break;

					default:
						//-- TODO: throw exception
						break;
				}
			}

	};
	
#endif