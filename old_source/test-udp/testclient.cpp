#include <string>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <cstdio>

using namespace std;

int main(int argv, char** args){

	string serverAddress = "149.56.142.13";
	int serverport = 1992;
	
	struct sockaddr_in unSockAddr;
	unSockAddr.sin_family = AF_INET;
	unSockAddr.sin_port = htons(serverport);
	inet_aton(serverAddress.c_str(), &unSockAddr.sin_addr);
	
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	connect(sock, (struct sockaddr*) &unSockAddr, sizeof(unSockAddr));
	
	char buffer[100] = "OK IM CHO";
	send(sock, buffer, 100, 0);
	printf("send: %s", buffer);
	
	struct sockaddr_in sender;
	socklen_t senderLen = sizeof(sender);
	recvfrom(sock, buffer, 100, 0, (struct sockaddr*) &sender, &senderLen);
	printf("revc %s", buffer);
	
}
