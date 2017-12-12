/*
	camclient2.exe [server address]
*/

#include <iostream>
#include <time.h>
#include <thread>

#include "../connector/connector.h"

#include "../src/utils/camera-util.h"
#include "../src/utils/utils-functions.h"

#define RETRY_TIME 5
#define SVC_CONNECTOR 0
#define UDP_CONNECTOR 1

using namespace std;

const uint32_t bufferSize = 1400;
uint8_t buffer[bufferSize] = "";

bool working = true;

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

void sendPacket(Connector* endpoint, uint8_t* imgData, int imgSize, int frameSeq) {
	//TODO: remove frameSeq

	if(endpoint==NULL) {
		return;
	}

	// static const uint32_t bufferSize = 1400;
	// static uint8_t buffer[bufferSize] = "";
	// printf("1");

	int packets = imgSize/(bufferSize-1);
	buffer[0] = 0x01;
	memcpy(buffer+1, &imgSize, 4);
	memcpy(buffer+1+4, &frameSeq, 4);
	for (int i=0;i<RETRY_TIME;i++){
		endpoint->sendData(buffer, 1+4+4);
	}

	buffer[0] = 0x02;
	for (int i = 0; i < packets; ++i)
	{
		memcpy(buffer+1, imgData+i*(bufferSize-1), bufferSize-1);
		endpoint->sendData(buffer,bufferSize);
	}

	int lastPacketSize = imgSize % (bufferSize-1);
	if(lastPacketSize != 0) {
		memcpy(buffer+1, imgData+packets*(bufferSize-1), lastPacketSize);
		endpoint->sendData(buffer,lastPacketSize+1);
	}

	buffer[0] = 0x03;
	for (int i=0;i<RETRY_TIME;i++){
		endpoint->sendData(buffer, 1);
	}

	printf("Frame %d sent, framesize = %d\n", frameSeq, imgSize);
}

void sendStream(Connector* endpoint)
{
	initFFmpeg(1);
	AVFormatContext *inFormatCtx = NULL;
	AVCodecContext *pCodecCtx = NULL;
	int videoStream;

	if(!openCamera(&inFormatCtx, &pCodecCtx, &videoStream)){
		return;
	}
	// if(inFormatCtx == NULL || pCodecCtx==NULL) {
	// 	return;
	// }

	int width = pCodecCtx->width;
	int height = pCodecCtx->height;

	AVFrame *pFrame = NULL;
	pFrame=av_frame_alloc();

	AVFrame *pFrameYUV420 = NULL;
	pFrameYUV420 = new_av_frame(AV_PIX_FMT_YUV420P, width, height);

	/* video encoder*/
	AVCodecContext* encoderCtx;
	initEncoderContext(&encoderCtx, width, height);

	struct SwsContext *sws_ctx_YUV420P = NULL;
	sws_ctx_YUV420P = sws_getContext(pCodecCtx->width,
	    pCodecCtx->height,
	    pCodecCtx->pix_fmt,
	    pCodecCtx->width,
	    pCodecCtx->height,
	    PIX_FMT_YUV420P,
	    SWS_BILINEAR,
	    NULL,
	    NULL,
	    NULL
	    );

	// Graphics* g = new Graphics(pCodecCtx->width,  pCodecCtx->height, "My Window");
	// if(strcmp(g->getError(), "") != 0) {
	// 	printf("SDL error: %s\n", g->getError());
	// 	return;
	// }

	/* Send the camera resolution */
	uint8_t buff[9];
	buff[0] = 0x00;
	memcpy(buff+1, &(pCodecCtx->width), 4);
	memcpy(buff+1+4, &(pCodecCtx->height), 4);
	for (int i = 0; i < 9; ++i)
	{
		printf("%d ", buff[i]);
	}
	for (int i = 0; i < RETRY_TIME; ++i)
	{
		endpoint->sendData(buff, 9);
	}

	/* Prepare for the main loop */
	SDL_Event       event;

	SDL_Rect sdlRect;  
    sdlRect.x = 0;  
    sdlRect.y = 0;  
    sdlRect.w = pCodecCtx->width;  
    sdlRect.h = pCodecCtx->height;  

	AVPacket packet;
	AVPacket outPacket;
	int gotOutput;
	int frameFinished;
	
	int frameSeq = 1;
	while(working)
    {
        av_read_frame(inFormatCtx, &packet);
        
        if(packet.stream_index==videoStream) {
	    	
	    	avcodec_decode_video2(pCodecCtx, pFrame, &frameFinished, &packet);
	    	
	    	if(frameFinished) {	    
				sws_scale(sws_ctx_YUV420P, (uint8_t const * const *)pFrame->data,
				  pFrame->linesize, 0, pCodecCtx->height,
				  pFrameYUV420->data, pFrameYUV420->linesize);
				
				// g->displayFFmpegYUVFrame(pFrameYUV420, &sdlRect);

				//encode frame to video
				av_init_packet(&outPacket);
	          	outPacket.data = NULL;
	          	outPacket.size = 0;
          		
          		pFrameYUV420->pts = (1.0 / 30) * 90 * frameSeq++;

          		if (avcodec_encode_video2(encoderCtx, &outPacket, pFrameYUV420, &gotOutput) < 0) {
			        fprintf(stderr, "Failed to encode frame\n");
			        continue;
			    }
				

			    if(gotOutput) {
			    	//send outPacket

			    	sendPacket(endpoint, outPacket.data, outPacket.size, frameSeq);
			    }

			    av_free_packet(&outPacket);
			}
        }

        av_free_packet(&packet);
		SDL_Delay(50);
		// SDL_PollEvent(&event);
  //       if(event.type == SDL_QUIT) {
		// 	SDL_Quit();
		// 	break;
		// }
    }
		// printf("\nimage sended!\n");
}

int main(int argc, char** argv){

	//int RETRY_TIME = atoi(argv[2]);

	char hostAddr[16];

	if (argc>1){
		strcpy(hostAddr, argv[1]);
	}
	else {
		strcpy(hostAddr, "192.168.43.43");
	}

	Connector* endpoint;
	
	if(argc > 2 && strcmp(argv[2],"--udp")==0) {
		endpoint = UDP_Connector::get_client_instance(hostAddr);
	}
	if(argc > 2) {
		if(strcmp(argv[2],"--udp")==0) {
			endpoint = UDP_Connector::get_client_instance(hostAddr);
		}
		else if(strcmp(argv[2],"--tcp")==0) {
			endpoint = TCP_Connector::get_client_instance(hostAddr);
		}
	}
	else {
		endpoint = SVC_Connector::get_client_instance(hostAddr);
	}

	thread tid(sendStream, endpoint);
	getchar();

	working = false;
	
}

