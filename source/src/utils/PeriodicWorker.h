#ifndef __TOM_PERIODIC_WORKER__
#define __TOM_PERIODIC_WORKER__

	#include "utils-functions.h"

	#define PERIODIC_SIGNAL SIGALRM

	class PeriodicWorker{
		private:
			timer_t timer;
			pthread_t worker;
			volatile bool working;
			void (*handler)(void*);
			void* args;
			int interval;
			
			static void* handling(void* args);
			
		public:
			PeriodicWorker(int interval, void (*handler)(void* args), void* args);
			~PeriodicWorker();			
			void stopWorking();
	};
	
	//--	PERIODIC WORKER
	PeriodicWorker::PeriodicWorker(int interval, void (*handler)(void*), void* args){
		this->interval = interval;
		this->working = true;
		this->handler = handler;
		this->args = args;
		
		pthread_attr_t threadAttr;
		pthread_attr_init(&threadAttr);
		pthread_create(&this->worker, &threadAttr, handling, this);
	}
	void PeriodicWorker::stopWorking(){
		//--	disarm automatic
		working = false;
		pthread_join(this->worker, NULL);
		timer_delete(this->timer);
		printf("\nperiodic worker stopped");
	}

	void* PeriodicWorker::handling(void* args){
		PeriodicWorker* pw = (PeriodicWorker*)args;
		
		struct sigevent evt;
		evt.sigev_notify = SIGEV_SIGNAL;
		evt.sigev_signo = PERIODIC_SIGNAL;
		evt.sigev_notify_thread_id = pthread_self();
		timer_create(CLOCK_REALTIME, &evt, &pw->timer);

		struct itimerspec time;
		time.it_interval.tv_sec=pw->interval/1000;
		time.it_interval.tv_nsec=(pw->interval - time.it_interval.tv_sec*1000)*1000000;
		time.it_value.tv_sec=pw->interval/1000;
		time.it_value.tv_nsec=(pw->interval - time.it_value.tv_sec*1000)*1000000;
		timer_settime(pw->timer, 0, &time, NULL);		
		
		bool waitrs;
		while (pw->working){
			//--	wait signal then perform handler
			waitrs = waitSignal(PERIODIC_SIGNAL);
			if (waitrs){
				//--	perform handler
				pw->handler(pw->args);
			}
			else{
				//--	SIGINT caught
				printf("\nperiodic worker got SIGINT, stop working");
				pw->stopWorking();
			}
		}
	}

	PeriodicWorker::~PeriodicWorker(){		
	}
	
#endif
