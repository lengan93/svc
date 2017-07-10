/**
	/.mnclient.exe filename
*/

#include <fstream>
#include <time.h>
#include <cstring>

#include "multinet.h"

using namespace std;

	    
MutexedQueue<MNPacket*> outgoingPackets;
// MutexedQueue<MNPacket*> incomingPackets;

int GetFileSize(std::string filename){
    ifstream file(filename.c_str(), ios::binary | ios::ate);
	return file.tellg();
}

float timeDistance(const struct timespec* greater, const struct timespec* smaller){
	float sec = greater->tv_sec - smaller->tv_sec;
	float nsec;
	if (greater->tv_nsec < smaller->tv_nsec){
		sec -= 1;
		nsec = greater->tv_nsec + 1000000000 - smaller->tv_nsec;
	}
	else{
		nsec = greater->tv_nsec - smaller->tv_nsec;
	}
	nsec /= 1000000000;
	sec += nsec;
	return sec;
}

void sendingHandler() {
	int sock, tosize;
	struct sockaddr_in server;

    //Create socket
    sock = socket(AF_INET , SOCK_DGRAM , 0);
    if (sock == -1)
    {
        printf("Could not create socket");
    }
     
    server.sin_addr.s_addr = inet_addr("192.168.0.11");
    // server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons( 8888 );
	tosize = sizeof server;

	MNPacket* packet;

	while(1) {
		packet = outgoingPackets.dequeueWait(1000);
		if(packet != NULL) {
			if(sendto(sock, packet->msg, packet->len, 0, (sockaddr *)&server, tosize)<0) {
				perror("sendto()");
			}
			printf("%d\n", ((uint8_t*)packet->msg)[0]);
			delete packet;
		}
	}

}

void sendingHandler2() {
	MNPacket* packet;

	int sock, tosize;
	struct sockaddr_in server;

    //Create socket
    sock = socket(AF_INET , SOCK_DGRAM , 0);
    if (sock == -1)
    {
        printf("Could not create socket");
    }
     
    server.sin_addr.s_addr = inet_addr("192.168.43.149");
    // server.sin_addr.s_addr = inet_addr("192.168.0.11");
    // server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons( 8888 );
	tosize = sizeof server;

	while(1) {
		packet = outgoingPackets.dequeueWait(1000);
		if(packet != NULL) {
			if(sendto(sock, packet->msg, packet->len, 0, (sockaddr *)&server, tosize)<0) {
				perror("sendto2()");
			}
			printf("%d\n", ((uint8_t*)packet->msg)[0]);
			delete packet;
		}
	}

}

int main(int argc, char** argv){

	if (argc>1){

		int RETRY_TIME = 10;
		
		int sock, serverSize;
		struct sockaddr_in client, server;

	    //Create socket
	    sock = socket(AF_INET , SOCK_DGRAM , 0);
	    if (sock == -1)
	    {
	        printf("Could not create socket");
	    }
	     
	    client.sin_addr.s_addr = INADDR_ANY;
	    // client.sin_addr.s_addr = inet_addr("127.0.0.1");
	    client.sin_family = AF_INET;
	    client.sin_port = htons( 8888 );
    	serverSize = sizeof server;

    	bind(sock, (struct sockaddr *)&client, sizeof(client));

		struct timespec startingTime;
		struct timespec echelon;
		clock_gettime(CLOCK_REALTIME, &startingTime);

		clock_gettime(CLOCK_REALTIME, &echelon);
		// printf("\n[%0.2f] Connection established.\n", timeDistance(&echelon, &startingTime));
		
		thread sendingThread(sendingHandler);
		thread sendingThread2(sendingHandler2);

		uint32_t bufferSize = 1300;
		uint8_t buffer[bufferSize+1];
							
		//-- send the file throw this connection
		string fileName = string(argv[1]);
		int fileSize = GetFileSize(fileName);
		if (fileSize >=0){
			printf("Sending file: %s, size: %d\n", fileName.c_str(), fileSize);					
							
			//-- firstly send the file description, 4 byte filesize, then the rest will be fileName
			buffer[0]=0x01;
			memcpy(buffer+1, &fileSize, 4);
			memcpy(buffer+1+4, (uint8_t*)fileName.c_str(), fileName.size());
			MNPacket* packet;
			for (int i=0;i<RETRY_TIME;i++){
				packet = new MNPacket(buffer, 1+4+fileName.size());
				outgoingPackets.enqueue(packet);
				// sendto(sock, buffer, 1+4+fileName.size(), 0, (sockaddr *)&server, tosize);
			}						
	
			//-- then send the content
			if (fileSize>0){
				ifstream bigFile(argv[1]);
				int blocsize;
				buffer[0] = 0x02;
				while (bigFile){
					blocsize = bufferSize;
					bigFile.read((char*)buffer+1, blocsize);
					if(bigFile.eof()) {
						blocsize = bigFile.gcount();
					}

					packet = new MNPacket(buffer, blocsize+1);
					outgoingPackets.enqueue(packet);

					// sendto(sock, buffer, blocsize+1, 0, (sockaddr *)&server, tosize);

				}													
				bigFile.close();
			}
			
			//-- then send terminating packets
			buffer[0] = 0x03;
			for (int i=0;i<RETRY_TIME;i++){
				packet = new MNPacket(buffer, 1);
				outgoingPackets.enqueue(packet);
				// sendto(sock, buffer, 1, 0, (sockaddr *)&server, tosize);

			}
			buffer[0] = 0x00;

			//-- read to check that server send terminating signal
			clock_gettime(CLOCK_REALTIME, &echelon);
			printf("[%0.2f] All data sent, waiting ACK\n", timeDistance(&echelon, &startingTime));
			// printf("\n%d packets sent", counter); fflush(stdout);
			
			bool fileSent = false;
			int n;
			do{
				// if (connect.recv(buffer, 1300) > 0){
				if((n = recvfrom(sock, buffer, 1300, 0, (sockaddr *)&server, (socklen_t*)&serverSize)) < 0)
				{
				    perror("recvfrom()");
				    exit(1);
				}
					if (buffer[0] = 0x03 && buffer[1]==0xFF){
						fileSent = true;																		
					}
				// }
			}
			while (!fileSent);

			clock_gettime(CLOCK_REALTIME, &echelon);
			float totalTime = timeDistance(&echelon, &startingTime);
			printf("[%0.2f] File sent, average speed: %0.0f KB/s\n", totalTime, fileSize/totalTime/1024);

			clock_gettime(CLOCK_REALTIME, &echelon);
			printf("[%0.2f] Program terminated\n", timeDistance(&echelon, &startingTime));
			getchar();
		}
	}
		
}
