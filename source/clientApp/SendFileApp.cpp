#include <iostream>

#include "../src/svc/SVC.h"
#include "../src/svc/host/SVCHostIP.h"
#include "../src/svc/authenticator/SVCAuthenticatorSharedSecret.h"


using namespace std;

int GetFileSize(std::string filename){
    ifstream file(filename.c_str(), ios::binary | ios::ate);
	return file.tellg();
}

int main(int argc, char** argv){

	const int RETRY_TIME = 5;

	if (argc>1){	
		string appID = string("SEND_FILE_APP");
		SVCHost* remoteHost = new SVCHostIP("149.56.142.13");
		SVCAuthenticatorSharedSecret* authenticator = new SVCAuthenticatorSharedSecret("./private/sharedsecret");
	
		try{
			SVC* svc = new SVC(appID, authenticator);		
			SVCEndpoint* endpoint = svc->establishConnection(remoteHost, 0);
			if (endpoint!=NULL){
				if (endpoint->negotiate()){
					printf("\nConnection established.");		
					
					uint32_t bufferSize = 1400;
					uint8_t buffer[bufferSize+1] = "";
										
					//-- send the file throw this connection
					string fileName = string(argv[1]);
					int fileSize = GetFileSize(fileName);
					if (fileSize > 0){
						printf("\nSending file: %s, size: %d", fileName.c_str(), fileSize); fflush(stdout);
						ifstream bigFile(argv[1]);
										
						//-- firstly send the file description, 4 byte filesize, then the rest will be fileName
						buffer[0]=0x01;
						memcpy(buffer+1, &fileSize, 4);
						memcpy(buffer+1+4, (uint8_t*)fileName.c_str(), fileName.size());
						for (int i=0;i<RETRY_TIME;i++){
							endpoint->sendData(buffer, 1+4+fileName.size());
						}						
				
						//-- then send the content
						buffer[0] = 0x02;
						while (bigFile && endpoint->isAlive()){
							bigFile.read((char*)buffer+1, bufferSize);							
							endpoint->sendData(buffer, bufferSize);
						}													
						bigFile.close();
						
						//-- then send terminating packets
						buffer[0] = 0x03;
						for (int i=0;i<RETRY_TIME;i++){
							endpoint->sendData(buffer, 1);
						}
						
						//-- read to check that server send terminating signal
						printf("\nAll data sent, waiting for terminating signal"); fflush(stdout);
						bool fileSent = false;
						do{
							if (endpoint->readData(buffer, &bufferSize, -1) == 0){
								if (buffer[0] = 0x03){
									fileSent = true;
									int receivedSize = *((int*)(buffer+1));
									printf("\nFile sent %d/%d bytes, lost rate: %0.2f%\n", receivedSize, fileSize, (1.0 - (float)(receivedSize)/fileSize)*100);
								}
							}
						}
						while (!fileSent);
					}
					else{
						printf("\nFile not valid\n");
					}										
				}
				else{
					printf("\nCannot establish connection. Program terminated.\n");
				}
				delete endpoint;
			}
			svc->shutdownSVC();
			delete svc;		
		}
		catch (const char* str){
			printf("\nError: %s\n", str);
		}
		
		delete authenticator;
		delete remoteHost;
	}
		
}
