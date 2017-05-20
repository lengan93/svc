#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <string>
#include <unistd.h>
#include <errno.h>
#include <cstdio>

using namespace std;

int main(int argc, char** argv){
	int sock = socket(AF_INET, SOCK_DGRAM, 0);

	struct sockaddr_in addr;
	inet_pton(AF_INET, "0.0.0.0", &(addr.sin_addr));
	addr.sin_port = htons(9293);
	addr.sin_family = AF_INET;

	char buffer[1000];
	memset(buffer, 0 , 1000);
	if (bind(sock, (struct sockaddr*) &addr, sizeof(addr)) == 0){
		printf("listening...\n");
		recv(sock, buffer, 1000, 0);
		printf("receiver: %s\n", buffer);
		return 0;
	}
	else{
		printf("bind failed, error: %d\n", errno);
		return -1;
	}
}