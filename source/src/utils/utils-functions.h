#ifndef __TOM_UTILS_FUNCTIONS__
#define __TOM_UTILS_FUNCTIONS__

	#include <csignal>		//-- for signal
	#include <sys/time.h>	//-- for time
	#include <cstdint>  	//-- for 'uintx_t'
	#include <cstdio>		//-- for 'printf'
	#include <pthread.h>	//-- for 'pthread_self()'
	
	#define sigev_notify_thread_id _sigev_un._tid
	
	//--	print a buffer in HEX
	static inline void printBuffer(const uint8_t* data, size_t len){
		for (int i=0;i<len;i++){
			printf("%02x ", data[i]);
		}
		printf("\n");
	}
	
	static inline void printBitString(const uint8_t* data, size_t len){
		for (int i=0;i<len;i++){
			uint8_t b = data[i];
			for (int j=7;j>=0;j--){
				printf("%d", ((b&(0x01<<j))>>j));				
			}
		}
	}	

	//--	block and wait for the presence of a signal
	//--	return FALSE if the waiting is interrupted by a SIGINT
	static inline bool waitSignal(int waitingSignal){		
		//block the waiting signal		
		sigset_t sig;
		//sigset_t oldset;
		sigemptyset(&sig);
		sigaddset(&sig, waitingSignal);
		sigaddset(&sig, SIGINT);	//-- interupt case
		return waitingSignal == sigwaitinfo(&sig, NULL);;
	}

	//--	timeoutSignal and waitingSignal must be differrent, otherwise the behavior is undefined
	//--	return TRUE if caught signal is correct, otherwise return FALSE
	static inline bool waitSignal(int waitingSignal, int timeout){
		sigset_t sig;
		sigemptyset(&sig);
		sigaddset(&sig, waitingSignal);
		sigaddset(&sig, SIGINT);
	
		struct timespec timeoutSpec;
		timeoutSpec.tv_sec=timeout/1000;
		timeoutSpec.tv_nsec=(timeout - timeoutSpec.tv_sec*1000)*1000000;
		return waitingSignal == sigtimedwait(&sig, NULL, &timeoutSpec);
	}	
#endif
