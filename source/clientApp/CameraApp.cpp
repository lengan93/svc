#include <opencv2/highgui/highgui.hpp>
#include <iostream>
#include <time.h>

#include "../src/svc/SVC.h"
#include "../src/svc/host/SVCHostIP.h"
#include "../src/svc/authenticator/SVCAuthenticatorSharedSecret.h"

#define RETRY_TIME 5

using namespace cv;

using namespace std;

// int GetFileSize(std::string filename){
//     ifstream file(filename.c_str(), ios::binary | ios::ate);
// 	return file.tellg();
// }

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

void sendStream(void *arg)
{
	// printf("0");
	SVCEndpoint* endpoint = (SVCEndpoint*) arg;

	VideoCapture capture(0); // open the default camera
 
    if( !capture.isOpened() )
    {
        printf( "ERROR: capture is NULL \n" );
        getchar();
        pthread_exit(NULL);
    }
		printf("1");

	uint32_t bufferSize = 5400;
	uint8_t buffer[bufferSize] = "";

    Mat frame;
    uint8_t* imgData;
    vector<unsigned char> encodebuff;

    namedWindow("MyVideo",CV_WINDOW_AUTOSIZE); //create a window called "MyVideo"

    if (!capture.read(frame)) //if not success, break loop
    {
       cout << "Cannot read the frame from video file" << endl;
       return;
    }

    // imshow("MyVideo", frame); //show the frame in "MyVideo" window
    // frame = (frame.reshape(0,1)); // to make it continuous

	int  imgSize;// = frame.total()*frame.elemSize();
	int frameSeq = 0;
	while(1)
    {

        // read a new frame from video

        capture.read(frame);
        imshow("MyVideo", frame); //show the frame in "MyVideo" window

        imencode(".jpg", frame, encodebuff);

		imgData = &encodebuff[0];
		imgSize = encodebuff.size();

		// printf("\n");
		// for (int i = 0; i < imgSize; ++i)
		// {
		// 	printf("%2x ", imgData[i]);
		// }
		// printf("\n");

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
		printf("\nFrame %d sent, framesize = %d, lastPacketSize = %d", frameSeq, imgSize, lastPacketSize);

		// bool goOn = false;
		// uint32_t s;
		// while(!goOn) {
		// 	if (endpoint->readData(buffer, &s, 40) == 0){
		// 		if (buffer[0] = 0x03 && frameSeq==*((int*)(buffer+1))){
		// 			goOn = true;																		
		// 		}
		// 	}
		// 	capture.read(frame);
  //       	imshow("MyVideo", frame);
		// }

		frameSeq++;
        if(waitKey(300) == 27) //wait for 'esc' key press for 30 ms. If 'esc' key is pressed, break loop
		{
		    cout << "esc key is pressed by user" << endl; 
		    break; 
		}
    }
		// printf("\nimage sended!\n");
}

int main(int argc, char** argv){

	//int RETRY_TIME = atoi(argv[2]);
	SVCHost* remoteHost;
	
	// string appID = string("CAMERA_APP");
	string appID = string("CAMERA_APP");
	// SVCHost* remoteHost = new SVCHostIP("149.56.142.13");
	if (argc>1){
		remoteHost = new SVCHostIP(argv[1]);
	}
	else {
		remoteHost = new SVCHostIP("192.168.43.149");
	}

	SVCAuthenticatorSharedSecret* authenticator = new SVCAuthenticatorSharedSecret("./private/sharedsecret");

	try{
		SVC* svc = new SVC(appID, authenticator);
		struct timespec startingTime;
		struct timespec echelon;
		clock_gettime(CLOCK_REALTIME, &startingTime);
		
		SVCEndpoint* endpoint = svc->establishConnection(remoteHost, 0);
		if (endpoint!=NULL){
			if (endpoint->negotiate()){
				clock_gettime(CLOCK_REALTIME, &echelon);
				printf("\n[%0.2f] Connection established.", timeDistance(&echelon, &startingTime)); fflush(stdout);

				//pthread_t my_thread;

					//pthread_create(&my_thread, NULL, sendStream, endpoint);
				sendStream(endpoint);
					// printf("\nPress any key to exit!\n");
					// getchar();

					//pthread_cancel(my_thread);

			}
			else{
				printf("\nCannot establish connection. Program terminated.\n");
			}
			delete endpoint;
		}
		else {
			printf("\nCannot create the endpoint. Program terminated.\n");
		}
		svc->shutdownSVC();
		delete svc;
		
		clock_gettime(CLOCK_REALTIME, &echelon);
		printf("\n[%0.2f] Program terminated\n", timeDistance(&echelon, &startingTime)); fflush(stdout);
	}
	catch (const char* str){
		printf("\nError: %s\n", str);
	}
	
	delete authenticator;
	delete remoteHost;
	
		
}
