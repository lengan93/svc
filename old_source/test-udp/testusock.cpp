#include <string>
#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <cstdio>

using namespace std;

int main(int argc, char** argv){

	//create a unix socket
	string path = string("/tmp/conkhikho");
	
	struct sockaddr_un sockUnAddr;
	int sockUn;
	
	sockUn = socket(AF_LOCAL, SOCK_DGRAM, 0);
	memset(&sockUnAddr, 0, sizeof(sockUnAddr));
	sockUnAddr.sun_family = AF_LOCAL;
	memcpy(sockUnAddr.sun_path, path.c_str(), path.size());
	bind(sockUn, (struct sockaddr*) &sockUnAddr, sizeof(sockUnAddr));
	
	//write something
	char buffer[100] = "HEHE";
	
	send(sockUn, buffer, 100, 0);
	
	printf("\nsent: %s", buffer);
	memset(buffer, 0, 100);
	
	recv(sockUn, buffer, 100, 0);
	printf("\nreceive: %s", buffer);
	
}
