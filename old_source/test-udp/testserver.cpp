#include <string>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
using namespace std;


int main(int argc, char** argv){

	//string serverAddress = "149.56.142.13";
	int serverport = 1992;
	
	struct sockaddr_in unSockAddr;
	unSockAddr.sin_family = AF_INET;
	unSockAddr.sin_port = htons(serverport);
	unSockAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	bind(sock, (struct sockaddr*) &unSockAddr, sizeof(unSockAddr));

	char buffer[100] = "";
	struct sockaddr_in clientAddr;
	socklen_t clientAddrLen = sizeof(clientAddr);
	
	recvfrom(sock, buffer, 100, 0, (struct sockaddr*) &clientAddr, &clientAddrLen);
	printf("revc %s", buffer);
	
	memcpy(buffer, "IM THE SERVER", 100);
	sendto(sock, buffer, 100, 0, (struct sockaddr*) &clientAddr, clientAddrLen);
	printf("send: %s", buffer);

}
