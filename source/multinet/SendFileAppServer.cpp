/**
	./mnserver.exe
*/

#include <iostream>
#include <fstream>
#include <time.h>
#include <cstring>

#include "multinet.h"

using namespace std;
using namespace std;

bool fileReceived = false;
bool headerReceived = false;
int fileSize;
int readSize = 0;
string fileName;

int GetFileSize(std::string filename){
    ifstream file(filename.c_str(), ios::binary | ios::ate);
	return file.tellg();
}

// void send_server_beat(void* args){
// 	uint8_t buffer[1];
// 	SVCEndpoint* ep = (SVCEndpoint*)args;
// 	buffer[0] = 0xFF;
// 	// ep->sendData(buffer, 1);
// 	if (headerReceived &!fileReceived){
// 		printf("\rReceived: %d/%d", readSize, fileSize); fflush(stdout);
// 	}
// }

int main(int argc, char** argv){

	// int RETRY_TIME = atoi(argv[1]);
	int RETRY_TIME = 10;

	printf("\nserver is listenning...\n"); 

	Multinet connect;
	connect.bind(1221);

	printf("Connection established!\n");
	
	uint32_t bufferSize = 1400;
	uint8_t buffer[bufferSize+1];
	
	ofstream* myFile;
	int blocs = 0;

	//-- try to read file size and name from the first message				
	int trytimes = 0;
	while (!fileReceived){
		if ((bufferSize = connect.recv(buffer, 1400)) > 0){
			trytimes = 0;
			switch (buffer[0]){
				case 0x01:
					if (!headerReceived){
						headerReceived = true;
						fileSize = *((int*)(buffer+1));
						fileName = string((char*)buffer+1+4, bufferSize-1-4);

						myFile = new ofstream(fileName.c_str());
						
						readSize = 0;
						printf("Receiving file: %s, size: %d\n", fileName.c_str(), fileSize); 
					}
					break;
					
				case 0x02:
					if (headerReceived){
						readSize+=bufferSize-1;
						blocs++;
						// printf("%d\n", bufferSize);

						//save to file
						myFile->write((char*)buffer+1, bufferSize-1);
					}
					break;
					
				case 0x03:
					if (!fileReceived){
						fileReceived = true;
					}
					break;
					
				default:
					break;
			}
		}
		else {
			trytimes++;
		}
		if(fileReceived || trytimes >= 3) {
			if (!fileReceived){
				fileReceived = true;
			}
			myFile->close();

			if (fileSize>0){
				printf("File received %d/%d bytes, lost rate: %0.2f\n", readSize, fileSize, (1.0 - (float)(readSize)/fileSize)*100);
				printf("blocs = %d\n", blocs);
			}
			else{
				printf("\nEmpty file received");
			}
													
			//printf("\nsend back 0x03"); 
			buffer[0]=0x03;						
			buffer[1]=0xFF;						
			for (int i=0; i<RETRY_TIME; i++){
				connect.send(buffer, 2);
				//printf(".");
			}
			
			break;
		}				
	}
	printf("\nProgram terminated!\n");
	getchar();	
}
