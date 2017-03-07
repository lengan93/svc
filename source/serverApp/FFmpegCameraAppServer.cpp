#include <opencv2/highgui/highgui.hpp>
#include <iostream>

#include "../src/utils/PeriodicWorker.h"
#include "../src/svc/SVC.h"
#include "../src/svc/host/SVCHostIP.h"
#include "../src/svc/authenticator/SVCAuthenticatorSharedSecret.h"

#include "../src/utils/camera-util.h"

#define RETRY_TIME 5

#define HEIGHT 480
#define WIDTH 640

using namespace cv;

using namespace std;

int frameSeq = 0;

void receiveStream(SVCEndpoint* endpoint) {
	initFFmpeg();

	uint32_t bufferSize = 1400;				
	uint8_t buffer[bufferSize];

	unsigned char* imgData;
	int imgSize;
	int blocs; //number of blocs of an image
	int trytimes = 0;
	int index = 0;
	bool firstPacketReceived = false;
	bool lastPacketReceived = false;
	int receivedBytes = 0;
	int frameFinished;

	AVCodecContext* decoderCtx;
	initDecoderContext(&decoderCtx, WIDTH, HEIGHT);

	AVFrame* decodedFrame = NULL;
	decodedFrame = av_frame_alloc();

	Graphics* g = new Graphics(WIDTH,  WIDTH, "My Window");
	if(strcmp(g->getError(), "") != 0) {
		printf("SDL error: %s\n", g->getError());
		return;
	}

	SDL_Event       event;

	SDL_Rect sdlRect;  
    sdlRect.x = 0;  
    sdlRect.y = 0;  
    sdlRect.w = WIDTH;  
    sdlRect.h = HEIGHT;

    AVPacket rcvPacket;

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
						av_init_packet(&rcvPacket);
	          			rcvPacket.data = imgData;
	          			rcvPacket.size = imgSize;

	          			avcodec_decode_video2(decoderCtx, decodedFrame, &frameFinished, &rcvPacket);
				    	if(frameFinished) {
				    		g->displayFFmpegYUVFrame(decodedFrame, &sdlRect);
				    	}
						delete [] imgData;

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
	}
}

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
				
				receiveStream(endpoint);

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
