#ifndef __TOM_PERIODIC_WORKER__
#define __TOM_PERIODIC_WORKER__

	#include <csignal>		//-- for signal
	#include <sys/time.h>	//-- for time
	
	class PeriodicWorker{
		private:
			pthread_t worker;
			volatile bool working;
			void (*handler)(void*);
			void* args;
			struct timespec loopTime;
			sigset_t sigset;
			
			static void* handling(void* args){
				PeriodicWorker* _this = (PeriodicWorker*)args;								
				int waitrs;
				while (_this->working){
					//--	waitrs will normally return -1, otherwise SIGINT
					waitrs = sigtimedwait(&_this->sigset, NULL, &_this->loopTime);
					if (waitrs == -1){
						//--	perform handler						
						_this->handler(_this->args);
					}
					else{
						//--	SIGINT caught	
						_this->stopWorking();
					}
				}
			}
			
		public:			
			~PeriodicWorker(){}				
			
			PeriodicWorker(int interval, void (*handler)(void* args), void* args){			
				this->working = true;
				this->handler = handler;
				this->args = args;
				
				this->loopTime.tv_sec = interval/1000;
				this->loopTime.tv_nsec = (interval-this->loopTime.tv_sec*1000)/1000000;
				sigemptyset(&this->sigset);
				sigaddset(&this->sigset, SIGINT);
				
				pthread_attr_t threadAttr;
				pthread_attr_init(&threadAttr);
				pthread_create(&this->worker, &threadAttr, handling, this);				
			}
			
			int waitStop(){
				return pthread_join(this->worker, NULL);
			}
			
			void stopWorking(){
				working = false;				
			}
	};
#endif
