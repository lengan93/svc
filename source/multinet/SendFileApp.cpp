/**
	/.mnclient.exe filename
*/

#include <fstream>
#include <time.h>
#include <cstring>

#include "multinet.h"

using namespace std;

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

int main(int argc, char** argv){

	// int RETRY_TIME = atoi(argv[2]);
	int RETRY_TIME = 10;
	// int counter = 0;

	Multinet connect;
	// if (connect.bind(1221, "wlp8s0", "enp9s0") != 0) {
	// 	printf("error: bind\n");
	// }

	// if (connect.setInterface("wlp8s0") != 0) {
	// 	printf("error: setInterface\n");
	// }
		
	if (argc>1){
		// string hostAddr = "192.168.43.149";
		// if(argc > 2) {
		// 	hostAddr = argv[2];
		// }
		// SVCHost* remoteHost = new SVCHostIP(hostAddr);
		connect.setDstAddress(0,"192.168.0.11", 1221);
		connect.setDstAddress(1,"192.168.43.149", 1221);
		
		// connect.bind(1221);

		struct timespec startingTime;
		struct timespec echelon;
		clock_gettime(CLOCK_REALTIME, &startingTime);
		
	
		clock_gettime(CLOCK_REALTIME, &echelon);
		printf("\n[%0.2f] Connection established.\n", timeDistance(&echelon, &startingTime));
		
		uint32_t bufferSize = 1300;
		uint8_t buffer[bufferSize+1] = "";
							
		//-- send the file throw this connection
		string fileName = string(argv[1]);
		int fileSize = GetFileSize(fileName);
		if (fileSize >=0){
			printf("Sending file: %s, size: %d\n", fileName.c_str(), fileSize);					
							
			//-- firstly send the file description, 4 byte filesize, then the rest will be fileName
			buffer[0]=0x01;
			memcpy(buffer+1, &fileSize, 4);
			memcpy(buffer+1+4, (uint8_t*)fileName.c_str(), fileName.size());
			for (int i=0;i<RETRY_TIME;i++){
				// endpoint->sendData(buffer, 1+4+fileName.size());
				connect.send(buffer,1+4+fileName.size());
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

					// endpoint->sendData(buffer, blocsize+1);
					connect.send(buffer, blocsize+1);
				}													
				bigFile.close();
			}
			
			//-- then send terminating packets
			buffer[0] = 0x03;
			for (int i=0;i<RETRY_TIME;i++){
				// endpoint->sendData(buffer, 1);
				connect.send(buffer, 1);
			}
			buffer[0] = 0x00;
			
			//-- read to check that server send terminating signal
			clock_gettime(CLOCK_REALTIME, &echelon);
			printf("[%0.2f] All data sent, waiting ACK\n", timeDistance(&echelon, &startingTime));
			// printf("\n%d packets sent", counter); fflush(stdout);
			bool fileSent = false;
			do{
				if (connect.recv(buffer, 1300) > 0){
					if (buffer[0] = 0x03 && buffer[1]==0xFF){
						fileSent = true;																		
					}
				}
			}
			while (!fileSent);
			
			clock_gettime(CLOCK_REALTIME, &echelon);
			float totalTime = timeDistance(&echelon, &startingTime);
			printf("[%0.2f] File sent, average speed: %0.0f KB/s\n", totalTime, fileSize/totalTime/1024);

		// 		// }
		// 		// else{
		// 		// 	printf("\nFile not valid\n");
		// 		// }										
		// 	}
		// 	else{
		// 		printf("\nCannot establish connection. Program terminated.\n");
		// 	}
		// 	delete endpoint;
		// }
		// svc->shutdownSVC();
		// delete svc;
		
		clock_gettime(CLOCK_REALTIME, &echelon);
		printf("[%0.2f] Program terminated\n", timeDistance(&echelon, &startingTime));
		// }
		// catch (const char* str){
		// 	printf("\nError: %s\n", str);
		// }
		}
	}
		
}
