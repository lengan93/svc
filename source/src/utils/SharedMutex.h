#ifndef __TOM_SHARED_MUTEX__
#define __TOM_SHARED_MUTEX__

	#include "Queue.h"	
	#include <pthread.h>
	#include <csignal>
	#include "utils-functions.h"

	using namespace std;
	
	#define SHARED_MUTEX_SIGNAL SIGUSR1

	class SharedMutex{		
		private:		
			int readerPresence;	
			int writerPresence;						
			Queue<pthread_t>* readWaitQueue;
			Queue<pthread_t>* writeWaitQueue;
	
			pthread_mutexattr_t mutexAttr;
			pthread_mutex_t readerPresenceMutex;
			pthread_mutex_t writerPresenceMutex;
			pthread_mutex_t readWaitQueueMutex;
			pthread_mutex_t writeWaitQueueMutex;

		public:	

			SharedMutex(){
				this->readerPresence = 0;
				this->writerPresence = 0;
				this->readWaitQueue = new Queue<pthread_t>();
				this->writeWaitQueue = new Queue<pthread_t>();
				
				pthread_mutexattr_init(&this->mutexAttr);
				pthread_mutex_init(&this->readerPresenceMutex, &this->mutexAttr);
				pthread_mutex_init(&this->writerPresenceMutex, &this->mutexAttr);
				pthread_mutex_init(&this->readWaitQueueMutex, &this->mutexAttr);
				pthread_mutex_init(&this->writeWaitQueueMutex, &this->mutexAttr);
			}
		
			~SharedMutex(){
				delete this->readWaitQueue;
				delete this->writeWaitQueue;
			}
	
			int lock(){				
				pthread_mutex_lock(&writerPresenceMutex);
				writerPresence++;				
				if (writerPresence == 1){
					//--	we are the first writer
					pthread_mutex_unlock(&writerPresenceMutex);
					//--	check for reader(s)
					pthread_mutex_lock(&readerPresenceMutex);
					if (readerPresence==0){
						//--	there is no reader, we can lock
						pthread_mutex_unlock(&readerPresenceMutex);
						return 0;
					}
					else{
						pthread_mutex_unlock(&readerPresenceMutex);
						pthread_mutex_lock(&writeWaitQueueMutex);
						this->writeWaitQueue->enqueue(pthread_self());
						pthread_mutex_unlock(&writeWaitQueueMutex);
						//--	wait for the last reader to notify
						return waitSignal(SHARED_MUTEX_SIGNAL);						
					}
				}
				else{					
					//--	there are other writers, wait in queue to be notified	
					//--	this also means there is absolutely no reader									
					pthread_mutex_unlock(&writerPresenceMutex);
					//--	add this thread to queue
					pthread_mutex_lock(&writeWaitQueueMutex);
					this->writeWaitQueue->enqueue(pthread_self());
					pthread_mutex_unlock(&writeWaitQueueMutex);
					//--	wait for signal from preceeded writer
					return waitSignal(SHARED_MUTEX_SIGNAL);
				}
			}
	
			int lock_shared(){
				//--	check if there is any pending writer
				pthread_mutex_lock(&writerPresenceMutex);
				//printf("lockshare with writerPresence %d\n", writerPresence);
				if (writerPresence == 0){
					//--	no writer, we can lock_shared
					pthread_mutex_unlock(&writerPresenceMutex);
					pthread_mutex_lock(&readerPresenceMutex);
					readerPresence++;
					pthread_mutex_unlock(&readerPresenceMutex);
					return 0;
				}
				else{					
					//--	there is at least one writer has obtained the mutex or JUST WANTED TO enter the critical session
					//--	we can no more allow reader to enter the queue, but after the last writer releases the mutex								
					pthread_mutex_unlock(&writerPresenceMutex);
				
					//--	wait here for the last writer to notify
					pthread_mutex_lock(&readWaitQueueMutex);
					this->readWaitQueue->enqueue(pthread_self());
					pthread_mutex_unlock(&readWaitQueueMutex);
					int rs = waitSignal(SHARED_MUTEX_SIGNAL);
				
					if (rs==0){
						//--	notified, we can lock_shared
						pthread_mutex_lock(&readerPresenceMutex);
						readerPresence++;
						pthread_mutex_unlock(&readerPresenceMutex);
					}
					return rs;
				}
			}
	
			void unlock_shared(){
				pthread_mutex_lock(&readerPresenceMutex);
				//printf("unlock shared with readerPresence %d\n", readerPresence);
				if (readerPresence == 0){
					//--	there is no lock_shared to be unlock_shared
					pthread_mutex_unlock(&readerPresenceMutex);
				}
				else{
					readerPresence--;
					if (readerPresence == 0){
						pthread_mutex_unlock(&readerPresenceMutex);
						//--	we are the last reader, notify the first writer (if any) to lock
						pthread_t tid;
						pthread_mutex_lock(&writeWaitQueueMutex);
						if (this->writeWaitQueue->peak(&tid)){
							//--	this must be the first writer waiting
							//--	pthread_kill won't return error with a valid signal
							pthread_kill(tid, SHARED_MUTEX_SIGNAL);
							this->writeWaitQueue->dequeue();							
						}						
						pthread_mutex_unlock(&writeWaitQueueMutex);
					}
					else{
						pthread_mutex_unlock(&readerPresenceMutex);
					}
				}				
			}
	
			void unlock(){
				//--	check if there are other writer waiting
				pthread_mutex_lock(&writerPresenceMutex);
				//printf("unlock with writerPresence %d\n", writerPresence);
				if (writerPresence == 0){
					//---	no more lock to unlock
					pthread_mutex_unlock(&writerPresenceMutex);
				}
				else{
					writerPresence--;
					pthread_mutex_unlock(&writerPresenceMutex);
					//--	notify the next writer if any
					pthread_t tid;
					pthread_mutex_lock(&writeWaitQueueMutex);
					if (this->writeWaitQueue->peak(&tid)){
						//--	notify next writer
						pthread_kill(tid, SHARED_MUTEX_SIGNAL);
						this->writeWaitQueue->dequeue();
						pthread_mutex_unlock(&writeWaitQueueMutex);
					}
					else{			
						pthread_mutex_unlock(&writeWaitQueueMutex);
						//--	no more writer, notify all readers
						pthread_mutex_lock(&readWaitQueueMutex);
						while (this->readWaitQueue->peak(&tid)){
							pthread_kill(tid, SHARED_MUTEX_SIGNAL);
							this->readWaitQueue->dequeue();
						}
						pthread_mutex_unlock(&readWaitQueueMutex);
					}					
				}				
			}
	};

#endif
