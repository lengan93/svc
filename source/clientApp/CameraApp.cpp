#include <opencv2/highgui/highgui.hpp>
#include <iostream>
#include <time.h>

#include "../src/svc/SVC.h"
#include "../src/svc/host/SVCHostIP.h"
#include "../src/svc/authenticator/SVCAuthenticatorSharedSecret.h"

#define RETRY_TIME 5

using namespace cv;

using namespace std;

int GetFileSize(std::string filename){
    ifstream file(filename.c_str(), ios::binary | ios::ate);
	return file.tellg();
}

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

void *sendImgThread(void *arg)
{
		printf("0");
	SVCEndpoint* endpoint = (SVCEndpoint*) arg;

	VideoCapture capture(0); // open the default camera
 
    if( !capture.isOpened() )
    {
        printf( "ERROR: capture is NULL \n" );
        getchar();
        pthread_exit(NULL);
    }
		printf("1");

	uint32_t bufferSize = 1400;
	uint8_t buffer[bufferSize] = "";

    Mat frame;
    uint8_t* imgData;

    namedWindow("MyVideo",CV_WINDOW_AUTOSIZE); //create a window called "MyVideo"

	while(1)
    {
        // for (int i = 0; i < 10; ++i)
        // {
        // 	bool bSuccess = capture.read(frame); // read a new frame from video

	       //   if (!bSuccess) //if not success, break loop
	       //  {
	       //                 cout << "Cannot read the frame from video file" << endl;
	       //                 // break;
	       //                 return NULL;
	       //  }
        // }

        // read a new frame from video

        if (!capture.read(frame)) //if not success, break loop
        {
           cout << "Cannot read the frame from video file" << endl;
           break;
        }

        imshow("MyVideo", frame); //show the frame in "MyVideo" window
        frame = (frame.reshape(0,1)); // to make it continuous

		int  imgSize = frame.total()*frame.elemSize();
		imgData = frame.data;

		int packets = imgSize/(bufferSize-1);
		buffer[0] = 0x01;
		for (int i=0;i<RETRY_TIME;i++){
			endpoint->sendData(buffer, 1);
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
		// printf(".");
        if(waitKey(30) == 27) //wait for 'esc' key press for 30 ms. If 'esc' key is pressed, break loop
		{
		    cout << "esc key is pressed by user" << endl; 
		    break; 
		}
    }
		// printf("\nimage sended!\n");
}

int main(int argc, char** argv){

	//int RETRY_TIME = atoi(argv[2]);

	if (argc>1){
		// string appID = string("CAMERA_APP");
		string appID = string("SEND_FILE_APP");
		// SVCHost* remoteHost = new SVCHostIP("149.56.142.13");
		SVCHost* remoteHost = new SVCHostIP(argv[1]);
		
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

   					//pthread_create(&my_thread, NULL, sendImgThread, endpoint);
					sendImgThread(endpoint);
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
		
}
