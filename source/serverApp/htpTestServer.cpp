#include <iostream>

#include "../src/htp/HTP.h"


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

int main(int argc, char** argv){

	int RETRY_TIME = atoi(argv[1]);

	try{
		printf("\nserver is listenning..."); fflush(stdout);
		
		HtpSocket htpSock(8888);
		struct sockaddr_in client = {0};
		socklen_t fromsize;
		fromsize = sizeof client;

		uint32_t bufferSize = 1400;
		uint8_t buffer[bufferSize+1];
		
		ofstream* myFile = NULL;
		int blocs = 0;

		//-- try to read file size and name from the first message				
		int trytimes = 0;
		while (!fileReceived){
			if ((bufferSize = htpSock.recvfrom(buffer, 1400, 0, (struct sockaddr*) &client, &fromsize)) > 0){
				trytimes = 0;
				switch (buffer[0]){
					case 0x01:
						if (!headerReceived){
							headerReceived = true;
							fileSize = *((int*)(buffer+1));
							fileName = string((char*)buffer+1+4, bufferSize-1-4);

							myFile = new ofstream(fileName.c_str());
							
							readSize = 0;
							printf("\nReceiving file: %s, size: %d\n", fileName.c_str(), fileSize); fflush(stdout);
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
		}
		if(myFile != NULL)
			myFile->close();

		if (fileSize>0){
			printf("\nFile received %d/%d bytes, lost rate: %0.2f%\n", readSize, fileSize, (1.0 - (float)(readSize)/fileSize)*100); fflush(stdout);
			printf("\nblocs = %d", blocs);
		}
		else{
			printf("\nEmpty file received");
		}
												
		//printf("\nsend back 0x03"); fflush(stdout);
		buffer[0]=0x03;						
		buffer[1]=0xFF;						
		for (int i=0; i<RETRY_TIME; i++){
			htpSock.sendto(buffer, 2, 0, (struct sockaddr*) &client, fromsize);
			// endpoint->sendData(buffer, 2);
			//printf(".");
		}
	}
	catch (const char* str){
		printf("\nError: %s\n", str);
	}
	
}
