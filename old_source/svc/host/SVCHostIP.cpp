#include "SVCHostIP.h"

using namespace std;

SVCHostIP::SVCHostIP(string ipAddress){
	this->ipAddress = ipAddress;
	int result = inet_aton(ipAddress.c_str(), &(this->hostAddr));
	if (result == -1)
		throw "Invalid IP address";		
}

uint32_t SVCHostIP::getHostAddress(){
	return (uint32_t)(this->hostAddr.s_addr);
}
