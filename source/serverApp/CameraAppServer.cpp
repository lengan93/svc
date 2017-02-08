#include <opencv2/highgui/highgui.hpp>
#include <iostream>

#include "../src/utils/PeriodicWorker.h"
#include "../src/svc/SVC.h"
#include "../src/svc/host/SVCHostIP.h"
#include "../src/svc/authenticator/SVCAuthenticatorSharedSecret.h"

#define HEIGHT 480
#define WIDTH 640

using namespace cv;

using namespace std;

// bool fileReceived = false;
// bool headerReceived = false;
// int fileSize;
// int readSize = 0;
// string fileName;

int framesReceived = 0;

int GetFileSize(std::string filename){
    ifstream file(filename.c_str(), ios::binary | ios::ate);
	return file.tellg();
}

void send_server_beat(void* args){
	uint8_t buffer[1];
	SVCEndpoint* ep = (SVCEndpoint*)args;
	buffer[0] = 0xFF;
	ep->sendData(buffer, 1);
	if (framesReceived > 0){
		printf("\rReceived: %d frames", framesReceived); fflush(stdout);
	}
}

int main(int argc, char** argv){

	// int RETRY_TIME = atoi(argv[1]);

	string appID = string("SEND_FILE_APP");	
	SVCAuthenticatorSharedSecret* authenticator = new SVCAuthenticatorSharedSecret("./private/sharedsecret");
	
	try{
		SVC* svc = new SVC(appID, authenticator);		
		printf("\nserver is listenning..."); fflush(stdout);
		SVCEndpoint* endpoint = svc->listenConnection(SVC_DEFAULT_TIMEOUT);
		printf("1\n");
		if (endpoint!=NULL){
			printf("2\n");
			if (endpoint->negotiate()){
				printf("\nConnection established!");
				
				//pw to sent beat
				// PeriodicWorker* pw = new PeriodicWorker(1000, send_server_beat, endpoint);								
				
				// uint32_t bufferSize = 1400;
				// uint8_t buffer[bufferSize];
				
				// ofstream* myFile;

				//-- try to read file size and name from the first message

				Mat  img = Mat::zeros( HEIGHT,WIDTH, CV_8UC3);
				int  imgSize = img.total()*img.elemSize();
				uint8_t imgData[imgSize];
				fill(imgData, imgData+imgSize, 0);

   				uint32_t bufferSize = 5400;				
   				uint8_t buffer[bufferSize];

   				int blocs = imgSize/(bufferSize-1);

     			namedWindow("MyVideo",CV_WINDOW_AUTOSIZE); //create a window called "MyVideo"
        		imshow("MyVideo", img); //show the frame in "MyVideo" window
     			printf("\nwindow created!\n");

				int trytimes = 0;
				int index = 0;
				bool firstPacketReceived = false;
				bool lastPacketReceived = false;
				int lastPacketSize = imgSize % (bufferSize-1);

				while (trytimes < 3){
					if (endpoint->readData(buffer, &bufferSize, 1000) == 0){
						printf("\n%x\t%d\t%d",buffer[0], bufferSize, index);
						switch (buffer[0]){
							case 0x01:
								if(!firstPacketReceived) {
									firstPacketReceived = true;
									lastPacketReceived = false;
									index = 0;
									// printf("\nreceiving image");
								}
								break;
								
							case 0x02:
								if(index < blocs) {
									memcpy(imgData+index*(bufferSize-1), buffer+1, bufferSize-1);
									index++;
								}
								else if(index == blocs) { //last bloc
									memcpy(imgData+index*(bufferSize-1), buffer+1, lastPacketSize);
									index++;
								}

								// printf("\nreceive bloc %d", index);

								break;
								
							case 0x03:
								if(!lastPacketReceived) {
									lastPacketReceived = true;
									firstPacketReceived = false;
									framesReceived++;
									printf("\nframe %d received", framesReceived);
									// img = Mat(Size(HEIGHT, WIDTH), CV_8UC3, imgData).clone();
        							int ptr=0;        							
									for (int i = 0;  i < img.rows; i++) {
										for (int j = 0; j < img.cols; j++) {                                     
											img.at<cv::Vec3b>(i,j) = cv::Vec3b(buffer[ptr+ 0],buffer[ptr+1],buffer[ptr+2]);
											ptr=ptr+3;
										}
									}

        							imshow("MyVideo", img); //show the frame in "MyVideo" window

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
