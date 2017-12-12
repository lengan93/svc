#include <iostream>
#include <thread>

#include "../connector/connector.h"

#include "../src/utils/camera-util.h"
#include "../src/utils/MutexedQueue.h"
#include "../src/utils/utils-functions.h"

#define RETRY_TIME 5

using namespace std;

int frameSeq = 0;

// bool working = true;


void display_video(MutexedQueue<AVPacket*> *frameBuffer, int width, int height) {
	
	initFFmpeg();

	Graphics* g = new Graphics(width,  height, "My Window");
	if(strcmp(g->getError(), "") != 0) {
		printf("SDL error: %s\n", g->getError());
		return;
	}

	SDL_Event       event;

	SDL_Rect sdlRect;  
    sdlRect.x = 0;  
    sdlRect.y = 0;  
    sdlRect.w = width;  
    sdlRect.h = height;

    AVCodecContext* decoderCtx;
	initDecoderContext(&decoderCtx, width, height);

	AVFrame* decodedFrame = NULL;
	decodedFrame = av_frame_alloc();

	int frameFinished;

    while(1) {
    	AVPacket* framePacket = frameBuffer->dequeueWait(-1);
    	if(framePacket != NULL) {
    		// cout << endl << framePacket->size << "-" << framePacket->data;
    		avcodec_decode_video2(decoderCtx, decodedFrame, &frameFinished, framePacket);
    		// cout << "2";
    		av_free(framePacket);
			if(frameFinished) {
				g->displayFFmpegYUVFrame(decodedFrame, &sdlRect);
				SDL_Delay(50);
				SDL_PollEvent(&event);
		        if(event.type == SDL_QUIT) {
					g->close();
					break;
				}
			}
    	}
    }
	

	g->close();
	av_free(decodedFrame);
}

void receiveStream(Connector* endpoint) {

	uint32_t bufferSize = 1400;				
	uint8_t buffer[bufferSize];

	MutexedQueue<AVPacket*> frameBuffer;

	/* Get the camera resolution */
	int width = 0;
	int height = 0;
	for (int i = 0; i < 10; ++i)
	{
		endpoint->readData(buffer,&bufferSize);
		if(bufferSize == 9 && buffer[0] == 0x00) {
			// for (int j = 0; j < 9; ++j)
			// {
			// 	printf("%d ", buffer[j]);
			// }
			width = *((int*)(buffer+1));
			height = *((int*)(buffer+1+4));
			break;
		}
	}
	if(width==0 || height==0) {
		printf("Could not get camera resolution\n");
		return;
	}

	std::thread display(display_video, &frameBuffer, width, height);

	unsigned char* imgData;
	int imgSize;
	int blocs; //number of blocs of an image
	int trytimes = 0;
	int index = 0;
	bool firstPacketReceived = false;
	bool lastPacketReceived = false;
	int receivedBytes = 0;
	
    AVPacket* rcvPacket;

    int starting_time = getTime();
    int echelon1 = starting_time;
    int echelon2;
    float v_inst, v_avg;
    long total_size = 0;

	while (trytimes < 3){
		if (endpoint->readData(buffer, &bufferSize) == 0){
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
						memset(imgData, 0, imgSize);
						// printf("\nreceiving image");
						echelon1 = getTime();
					}
					break;
					
				case 0x02:
					if(receivedBytes < imgSize) {
						// if(index != 0) {
							memcpy(imgData+receivedBytes, buffer+1, bufferSize-1);

							receivedBytes += bufferSize-1;
						// }

						index++;
					}
					break;
					
				case 0x03:
					if(!lastPacketReceived) {
						lastPacketReceived = true;
						firstPacketReceived = false;

						//decode the image received
						// if(frameSeq == 50)
							// memset(imgData+imgSize/2, 0, imgSize-imgSize/2);
    					rcvPacket = new AVPacket;
						av_init_packet(rcvPacket);
	          			rcvPacket->data = imgData;
	          			rcvPacket->size = imgSize;

	          			frameBuffer.enqueue(rcvPacket);

	          			echelon2 = getTime();
	          			total_size += imgSize;
	          			v_inst = (imgSize/1024.0)/((echelon2 - echelon1)/1000.0);
	          			v_avg = (total_size/1024.0)/((echelon2 - starting_time)/1000.0);
						printf("\n %d\t%.3f Kb\t%.3f KB/s\t%.3f KB/s(avg)", frameSeq, imgSize/1000.0, v_inst, v_avg);
						// printf("\nframe %d (%d) received, v_inst = %f KB/s, v_avg = %f KB/s", frameSeq, imgSize, v_inst, v_avg);

						//delete [] imgData;
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

// void* process(void* arg) {
// 	SVCEndpoint* endpoint = (SVCEndpoint*) arg;
// 	if (endpoint->negotiate()){
// 		printf("\nConnection established!");
		
// 		receiveStream(endpoint);

// 		endpoint->shutdownEndpoint();			
// 		// printf("\nProgram terminated!\n");
// 	}
// 	else{
// 		printf("\nCannot establish connection!\n");
// 	}
// }

// void* mainLoop(void* arg) {
// 	string appID = string("CAMERA_APP");	
// 	SVCAuthenticatorSharedSecret* authenticator = new SVCAuthenticatorSharedSecret("./private/sharedsecret");
	
// 	try{
// 		SVC* svc = new SVC(appID, authenticator);		
// 		printf("\nserver is listenning..."); fflush(stdout);

// 		while(working) {
// 			SVCEndpoint* endpoint = svc->listenConnection(-1);
// 			// printf("1\n");
// 			if (endpoint!=NULL){
// 				// create a thread to process
// 				pthread_t thread_id;

// 			}
// 		}
		
// 			// printf("2\n");
// 		// 	if (endpoint->negotiate()){
// 		// 		printf("\nConnection established!");
// 		// 		if(argc == 1) {
// 		// 			receiveStream(endpoint);
// 		// 		}

// 		// 		endpoint->shutdownEndpoint();			
// 		// 		printf("\nProgram terminated!\n");
// 		// 	}
// 		// 	else{
// 		// 		printf("\nCannot establish connection!\n");
// 		// 	}
// 		// 	delete endpoint;
// 		// }
// 		// else {
// 		// 	printf("\nCannot create endpoint!\n");
// 		// }
// 		svc->shutdownSVC();
// 		delete svc;
// 	}
// 	catch (...){
// 		printf("\nError: cannot create an instance of SVC\n");
// 	}
	
// 	delete authenticator;
// }

int main(int argc, char** argv){

	Connector* endpoint;
	try {

		if(argc > 1) {
			if(strcmp(argv[1],"--udp")==0) {
				endpoint = UDP_Connector::get_server_instance();
			}
			else if(strcmp(argv[1],"--tcp")==0) {
				endpoint = TCP_Connector::get_server_instance();
			}
		}
		else {
			endpoint = SVC_Connector::get_server_instance();
		}

		if(endpoint != NULL) {
			// pthread_t tid;
			// pthread_create (&tid, NULL, &process, endpoint);
			receiveStream(endpoint);
		}
		else {
			printf("\nCannot establish connection\n");
		}
	}
	catch (const char* str){
		printf("\nError: %s\n", str);
	}

	// int RETRY_TIME = atoi(argv[1]);

	// pthread_create (&tid, NULL, &mainLoop, NULL);
	// char c;
	// do{
	// 	c = getchar();		
	// } while(c != 'q');

	// working = false;

	// pthread_join(tid, NULL);
	
}


/*
It's not multi-connections. The buffer queue is commun
*/