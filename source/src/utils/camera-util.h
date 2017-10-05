
#ifndef _CAMERA_UTIL_H
#define _CAMERA_UTIL_H

#include <SDL2/SDL.h>
#include <SDL2/SDL_thread.h>

extern "C" { 
	#include <libavcodec/avcodec.h> 
	#include <libavformat/avformat.h>
	#include <libswscale/swscale.h>
	#include <libavutil/error.h>
	#include <libavutil/imgutils.h>
	#include <libavdevice/avdevice.h>
}

class Graphics
{
private:
	char error[100];
	SDL_Window* sdlWindow;
	SDL_Renderer* sdlRenderer;

	SDL_Texture* sdlTexture;
public:
	
	Graphics(int windowWidth, int windowHeight, const char* windowTitle) {
		strcpy(error,"");

		if(SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER)) {
			strcpy(error,SDL_GetError());
			return;
		}

		sdlWindow = SDL_CreateWindow(windowTitle,  
	        SDL_WINDOWPOS_UNDEFINED,  
	        SDL_WINDOWPOS_UNDEFINED,  
	        windowWidth, windowHeight,  
	        0);  

	    if( !sdlWindow ) {  
	        strcpy(error, "Could not create window");  
	        return;
	    } 

	    sdlRenderer = SDL_CreateRenderer(sdlWindow, -1, SDL_RENDERER_TARGETTEXTURE);

	    sdlTexture = SDL_CreateTexture(  
	        sdlRenderer,  
	        SDL_PIXELFORMAT_YV12,  
	        SDL_TEXTUREACCESS_STREAMING,  
	        windowWidth,  
	        windowHeight);  

		if(!sdlTexture) {
			strcpy(error, "Could not create texture");
			return;
		}

		SDL_SetTextureBlendMode(sdlTexture,SDL_BLENDMODE_BLEND );
		printf("SDL initialized\n");
	}

	bool displayFFmpegYUVFrame(AVFrame* frame, SDL_Rect *sdlRect) {
		// printf("%d\n", frame->data[0][10]);
		SDL_UpdateYUVTexture( sdlTexture, sdlRect, frame->data[0], frame->linesize[0], 
			frame->data[1], frame->linesize[1], 
			frame->data[2], frame->linesize[2] );  
		SDL_RenderClear( sdlRenderer );  
        SDL_RenderCopy( sdlRenderer, sdlTexture, sdlRect, sdlRect );  
        SDL_RenderPresent( sdlRenderer ); 
        // printf(".\n");
        return true;
	}

	char* getError() {
		return error;
	}

	void close() {
		if(sdlWindow != NULL){
			SDL_DestroyWindow(sdlWindow);
		}

		if(sdlRenderer != NULL){
			SDL_DestroyRenderer(sdlRenderer);
		}
		
		if(sdlTexture != NULL){
			SDL_DestroyTexture(sdlTexture);
		}

	}

	~Graphics() {
		this->close();
	}
	
};

void initFFmpeg(int withDevice = 0) {
	avcodec_register_all();
	av_register_all();
	if(withDevice != 0) {
		avdevice_register_all(); // for device 
	}
}

bool openCamera(AVFormatContext **cameraFmtCtx, AVCodecContext **cameraCodecCtx, int* streamIndex) {
	//for linux only
	AVInputFormat *inputFormat = av_find_input_format("video4linux2");



	int code;
	char errbuf[100];
	code = avformat_open_input(cameraFmtCtx, "/dev/video0", inputFormat, NULL);
	if(code != 0) {
		av_strerror(code, errbuf, 100);
		printf("Couldn't open camera, error %d: %s\n", code, errbuf);
		return false;
	}

	if((code = avformat_find_stream_info(*cameraFmtCtx, NULL)) < 0){
		av_strerror(code, errbuf, 100);
		printf("avformat_find_stream_info: error %d - %s\n", code, errbuf);
		return false;
	}

	//find a video stream index
	int videoStream = -1;
	for(int i=0; i<(*cameraFmtCtx)->nb_streams; i++)
		if((*cameraFmtCtx)->streams[i]->codec->codec_type==AVMEDIA_TYPE_VIDEO) {
			videoStream=i;
			break;
		}
	if(videoStream == -1) {
	  	printf("cannot find a video stream\n");
		return false;
	}
	*streamIndex = videoStream;

	/*Get the camera decoder*/
	AVCodecContext* pCodecCtxOrig = (*cameraFmtCtx)->streams[videoStream]->codec;
	AVCodec *pCodec = NULL;

	// Find the decoder for the video stream
	pCodec = avcodec_find_decoder(pCodecCtxOrig->codec_id);
	if(pCodec==NULL) {
		fprintf(stderr, "Unsupported codec!\n");
		return false; // Codec not found
	}
	
	// Copy context
	*cameraCodecCtx = avcodec_alloc_context3(pCodec);
	// printf("5\n");
	if(avcodec_copy_context(*cameraCodecCtx, pCodecCtxOrig) != 0) {
		fprintf(stderr, "Couldn't copy codec context");
		return false; // Error copying codec context
	}
	avcodec_close(pCodecCtxOrig);

	// Open codec
	if(avcodec_open2(*cameraCodecCtx, pCodec, NULL) < 0) {
	  // Could not open codec
		fprintf(stderr, "Couldn't copy codec context");
	  	return false;
	}
	return true;
}

AVFrame* new_av_frame(AVPixelFormat pix_fmt, int width, int height) {
	AVFrame *pFrame = NULL;			//image from camera
	pFrame = av_frame_alloc();

	pFrame->format = pix_fmt;
    pFrame->width  = width;
    pFrame->height = height;

    av_image_alloc(pFrame->data, pFrame->linesize, width, height, pix_fmt, 32);

	// av_free(buffer);
	return pFrame;
}

bool initEncoderContext(AVCodecContext **encoderCtx, int width, int height) {
	AVCodec *encoder = avcodec_find_encoder(AV_CODEC_ID_H264);
    if(!encoder) {
    	printf("encode codec not found\n");
    	return false;
    }

    *encoderCtx = avcodec_alloc_context3(encoder);
    (*encoderCtx)->bit_rate 	= 	400000;
    (*encoderCtx)->width 		= 	width;;
    (*encoderCtx)->height 		= 	height;
    (*encoderCtx)->time_base 	= 	(AVRational){1,25};
    (*encoderCtx)->gop_size 	=	5;
    (*encoderCtx)->max_b_frames = 	1;
    (*encoderCtx)->pix_fmt 		= 	AV_PIX_FMT_YUV420P;

    if (avcodec_open2(*encoderCtx, encoder, NULL) < 0) {
    	printf("cannot open encode codec\n");
        return false;
	}
}

bool initDecoderContext(AVCodecContext **decoderCtx, int width, int height) {
	AVCodec *decoder = avcodec_find_decoder(AV_CODEC_ID_H264);
    if(!decoder) {
    	printf("decode codec not found\n");
    	return false;
    }

    *decoderCtx = avcodec_alloc_context3(decoder);
    (*decoderCtx)->width 		= 	width;;
    (*decoderCtx)->height 		= 	height;
    (*decoderCtx)->pix_fmt 		= 	AV_PIX_FMT_YUV420P;

    if (avcodec_open2(*decoderCtx, decoder, NULL) < 0) {
    	printf("cannot open decode codec\n");
        return false;
	}
}

#endif