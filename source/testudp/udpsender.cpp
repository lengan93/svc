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
	string data = "there is con khi";

	if (connect(sock, (struct sockaddr*) &addr, sizeof(addr)) == 0){
		send(sock, data.c_str(), strlen(data.c_str()), 0);
		printf("sent");
		return 0;
	}
	else{
		printf("sent failed, error: %d\n", errno);
		return -1;
	}
}