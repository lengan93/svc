#ifndef __TOM_SHARED_MUTEX__
#define __TOM_SHARED_MUTEX__

	#include "Queue.h"
	#include "Node.h"	
	#include <mutex>
	#include <csignal>

	using namespace std;
	
	#define SHARED_MUTEX_SIGNAL SIGUSR1

	class SharedMutex{	
	
		private:		
			int readerPresence;	
			int writerPresence;						
			Queue<pthread_t>* readWaitQueue;
			Queue<pthread_t>* writeWaitQueue;
	
			mutex readerPresenceMutex;
			mutex writerPresenceMutex;
			mutex readWaitQueueMutex;
			mutex writeWaitQueueMutex;

			int waitSignal(){
				sigset_t sigset;
				sigemptyset(&sigset);
				sigaddset(&sigset, SHARED_MUTEX_SIGNAL);
				/*	no need to check for caughtSignal because we only block only one signal	*/
				int caughtSignal;			
				int result = sigwait(&sigset, &caughtSignal);
				return result;
			}

		public:	

			SharedMutex(){
				this->readerPresence = 0;
				this->writerPresence = 0;
				this->readWaitQueue = new Queue<pthread_t>();
				this->writeWaitQueue = new Queue<pthread_t>();
			}
		
			~SharedMutex(){
				delete this->readWaitQueue;
				delete this->writeWaitQueue;
			}
	
			int lock(){				
				writerPresenceMutex.lock();
				writerPresence++;			
				//printf("lock with writerPresence %d\n", writerPresence);
				if (writerPresence == 1){
					//--	we are the first writer
					writerPresenceMutex.unlock();
					//--	check for reader(s)
					readerPresenceMutex.lock();
					if (readerPresence==0){
						//--	there is no reader, we can lock
						readerPresenceMutex.unlock();
						return 0;
					}
					else{
						readerPresenceMutex.unlock();												
						writeWaitQueueMutex.lock();
						this->writeWaitQueue->enqueue(pthread_self());
						writeWaitQueueMutex.unlock();
						//--	wait for the last reader to notify
						return waitSignal();						
					}
				}
				else{					
					//--	there are other writers, wait in queue to be notified	
					//--	this also means there is absolutely no reader									
					writerPresenceMutex.unlock();
					//--	add this thread to queue
					writeWaitQueueMutex.lock();
					this->writeWaitQueue->enqueue(pthread_self());
					writeWaitQueueMutex.unlock();
					//--	wait for signal from preceeded writer
					return waitSignal();
				}
			}
	
			int lock_shared(){
				//--	check if there is any pending writer
				writerPresenceMutex.lock();
				//printf("lockshare with writerPresence %d\n", writerPresence);
				if (writerPresence == 0){
					//--	no writer, we can lock_shared
					writerPresenceMutex.unlock();
					readerPresenceMutex.lock();
					readerPresence++;
					readerPresenceMutex.unlock();
					return 0;
				}
				else{					
					//--	there is at least one writer has obtained the mutex or JUST WANTED TO enter the critical session
					//--	we can no more allow reader to enter the queue, but after the last writer releases the mutex								
					writerPresenceMutex.unlock();
				
					//--	wait here for the last writer to notify
					readWaitQueueMutex.lock();
					this->readWaitQueue->enqueue(pthread_self());
					readWaitQueueMutex.unlock();
					int rs = waitSignal();
				
					if (rs==0){
						//--	notified, we can lock_shared
						readerPresenceMutex.lock();
						readerPresence++;
						readerPresenceMutex.unlock();
					}
					return rs;
				}
			}
	
			void unlock_shared(){
				readerPresenceMutex.lock();
				//printf("unlock shared with readerPresence %d\n", readerPresence);
				if (readerPresence == 0){
					//--	there is no lock_shared to be unlock_shared
					readerPresenceMutex.unlock();					
				}
				else{
					readerPresence--;
					if (readerPresence == 0){
						readerPresenceMutex.unlock();
						//--	we are the last reader, notify the first writer (if any) to lock
						pthread_t tid;
						writeWaitQueueMutex.lock();						
						if (this->writeWaitQueue->peak(&tid)){
							//--	this must be the first writer waiting
							//--	pthread_kill won't return error with a valid signal
							pthread_kill(tid, SHARED_MUTEX_SIGNAL);
							this->writeWaitQueue->dequeue();							
						}						
						writeWaitQueueMutex.unlock();						
					}
					else{
						readerPresenceMutex.unlock();						
					}
				}				
			}
	
			void unlock(){
				//--	check if there are other writer waiting
				writerPresenceMutex.lock();
				//printf("unlock with writerPresence %d\n", writerPresence);
				if (writerPresence == 0){
					//---	no more lock to unlock
					writerPresenceMutex.unlock();					
				}
				else{
					writerPresence--;
					writerPresenceMutex.unlock();
					//--	notify the next writer if any
					pthread_t tid;
					writeWaitQueueMutex.lock();
					if (this->writeWaitQueue->peak(&tid)){
						//--	notify next writer
						pthread_kill(tid, SHARED_MUTEX_SIGNAL);
						this->writeWaitQueue->dequeue();
						writeWaitQueueMutex.unlock();						
					}
					else{			
						writeWaitQueueMutex.unlock();		
						//--	no more writer, notify all readers
						readWaitQueueMutex.lock();
						while (this->readWaitQueue->peak(&tid)){
							pthread_kill(tid, SHARED_MUTEX_SIGNAL);
							this->readWaitQueue->dequeue();
						}
						readWaitQueueMutex.unlock();						
					}					
				}				
			}
	};

#endif
