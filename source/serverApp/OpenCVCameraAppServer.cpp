#include <opencv2/highgui/highgui.hpp>
#include <iostream>

#include "../src/utils/PeriodicWorker.h"
#include "../src/svc/SVC.h"
#include "../src/svc/host/SVCHostIP.h"
#include "../src/svc/authenticator/SVCAuthenticatorSharedSecret.h"

#define RETRY_TIME 5

#define HEIGHT 480
#define WIDTH 640

using namespace cv;

using namespace std;

int frameSeq = 0;

// int GetFileSize(std::string filename){
//     ifstream file(filename.c_str(), ios::binary | ios::ate);
// 	return file.tellg();
// }

// void send_server_beat(void* args){
// 	uint8_t buffer[1];
// 	SVCEndpoint* ep = (SVCEndpoint*)args;
// 	buffer[0] = 0xFF;
// 	ep->sendData(buffer, 1);
// 	if (frameSeq > 0){
// 		printf("\rReceived: %d frames", frameSeq); fflush(stdout);
// 	}
// }

int main(int argc, char** argv){

	// int RETRY_TIME = atoi(argv[1]);

	string appID = string("CAMERA_APP");	
	SVCAuthenticatorSharedSecret* authenticator = new SVCAuthenticatorSharedSecret("./private/sharedsecret");
	
	try{
		SVC* svc = new SVC(appID, authenticator);		
		printf("\nserver is listenning..."); fflush(stdout);
		SVCEndpoint* endpoint = svc->listenConnection(SVC_DEFAULT_TIMEOUT);
		// printf("1\n");
		if (endpoint!=NULL){
			// printf("2\n");
			if (endpoint->negotiate()){
				printf("\nConnection established!");
				
				//pw to sent beat
				// PeriodicWorker* pw = new PeriodicWorker(1000, send_server_beat, endpoint);								

				Mat  img = Mat::zeros( HEIGHT,WIDTH, CV_8UC3);;

				unsigned char* imgData;
				int imgSize;
				int blocs; //number of blocs of an image

   				uint32_t bufferSize = 5400;				
   				uint8_t buffer[bufferSize];

     			namedWindow("MyVideo",CV_WINDOW_AUTOSIZE); //create a window called "MyVideo"
        		imshow("MyVideo", img); //show the frame in "MyVideo" window
     			printf("\nwindow created!\n");

				int trytimes = 0;
				int index = 0;
				bool firstPacketReceived = false;
				bool lastPacketReceived = false;
				int receivedBytes = 0;

				while (trytimes < 3){
					if (endpoint->readData(buffer, &bufferSize, 1000) == 0){
						// printf("\n%x\t%d\t%d",buffer[0], bufferSize, index);
						switch (buffer[0]){
							case 0x01:
								if(!firstPacketReceived) {
									firstPacketReceived = true;
									lastPacketReceived = false;
									index = 0;
									receivedBytes = 0;

									imgSize = *((int*)(buffer+1));
									frameSeq = *((int*)(buffer+1+4));
									imgData = new unsigned char[imgSize];
									// printf("\nreceiving image");
								}
								break;
								
							case 0x02:
								if(receivedBytes < imgSize) {
									memcpy(imgData+receivedBytes, buffer+1, bufferSize-1);

									// printf("\n");
									// for (int i = receivedBytes; i < receivedBytes+bufferSize-1; ++i)
									// {
									// 	printf("%2x ", imgData[i]);
									// }
									// printf("\n");

									receivedBytes += bufferSize-1;

									index++;
								}
								break;
								
							case 0x03:
								if(!lastPacketReceived) {
									lastPacketReceived = true;
									firstPacketReceived = false;
									printf("\nframe %d received, frameSize = %d", frameSeq, imgSize);

									//decode the image received
        							vector<unsigned char> encodeImg(imgData, imgData+imgSize) ;
        							img = imdecode(encodeImg, CV_LOAD_IMAGE_COLOR);
        							encodeImg.clear();
									delete [] imgData;
        							imshow("MyVideo", img); //show the frame in "MyVideo" window

        							// send the ack
        	// 						buffer[0] = 0x03;
									// memcpy(buffer+1, &frameSeq, 4);
									// for (int i=0;i<RETRY_TIME;i++){
									// 	endpoint->sendData(buffer, 1+4);
									// }
								}
								break;
								
							default:
								break;
						}

					}
					else {
						trytimes++;
					}

					if(waitKey(30) == 27) //wait for 'esc' key press for 30 ms. If 'esc' key is pressed, break loop
					{
					    cout << "esc key is pressed by user" << endl; 
					    break; 
					}
				}

				// pw->stopWorking();
				// pw->waitStop();
				// delete pw;
								
				endpoint->shutdownEndpoint();			
				printf("\nProgram terminated!\n");
			}
			else{
				printf("\nCannot establish connection!\n");
			}
			delete endpoint;
		}
		else {
			printf("\nCannot create endpoint!\n");
		}
		svc->shutdownSVC();
		delete svc;
	}
	catch (...){
		printf("\nError: cannot create an instance of SVC\n");
	}
	
	delete authenticator;
}
