#ifndef __SVC_SHARED_MUTEX__
#define __SVC_SHARED_MUTEX__

	#include "Node.h"
	#include "SVC-header.h"
	#include <mutex>
	#include <csignal>

	using namespace std;
	
	/*	this is a normal non-mutexed queue	*/
	template <class T>
	class Queue{
		private:
			Node<T>* first;
			Node<T>* last;			
			int count;
		
		public:
	
			Queue(){
				this->first = NULL;
				this->last = NULL;
				this->count = 0;
			}
		
			~Queue(){
				while (this->notEmpty()){
					this->dequeue();
				}
			}
		
			bool notEmpty(){				
				return count>0;
			}

			void enqueue(T data){
				Node<T>* element = new Node<T>();
				element->setData(data);
				element->setNext(NULL);
				
				if (this->notEmpty()){	
					this->last->setNext(element);
					this->last = element;
				}
				else{
					this->first = element;
					this->last = element;			
				}
				this->count++;
			}
			
			void dequeue(){
				if (this->notEmpty()){				
					Node<T>* tmp = this->first;
					this->first = tmp->getNext();				
					this->count--;
					delete tmp;
				}
			}
		
			bool peak(T* data){			
				if (this->notEmpty()){
					*data = this->first->getData();				
					return true;
				}
				return false;				
			}
	};

	class shared_mutex{	
	
		private:		
			int readerPresence;	
			int writerPresence;						
			Queue<pthread_t>* readWaitQueue;
			Queue<pthread_t>* writeWaitQueue;
	
			mutex readerPresenceMutex;
			mutex writerPresenceMutex;
			mutex readWaitQueueMutex;
			mutex writeWaitQueueMutex;

			void waitSignal(){
				sigset_t sigset;
				sigemptyset(&sigset);
				sigaddset(&sigset, SVC_SHARED_MUTEX_SIGNAL);
				/*	no need to check for caughtSignal because we only block only one signal	*/
				int caughtSignal;
				/*	TODO: check return value of sigwait	*/
				int result = sigwait(&sigset, &caughtSignal);
				if (result!=0) printf("sigwait problem");
				return;
			}

		public:	

			shared_mutex(){
				this->readerPresence = 0;
				this->writerPresence = 0;
				this->readWaitQueue = new Queue<pthread_t>();
				this->writeWaitQueue = new Queue<pthread_t>();
			}
		
			~shared_mutex(){
				delete this->readWaitQueue;
				delete this->writeWaitQueue;
			}
	
			void lock(){
				/*	set writer presence if not set yet	*/
				writerPresenceMutex.lock();
			
				//printf("lock with writerPresence %d\n", writerPresence);
				if (writerPresence == 0){
					/* there is no writer, we are the only one	*/
					writerPresenceMutex.unlock();
					/*	check for reader(s)	*/
					readerPresenceMutex.lock();
					if (readerPresence==0){
						/*	there is no reader, we can lock	*/
						readerPresenceMutex.unlock();
						writerPresenceMutex.lock();
						writerPresence++;
						writerPresenceMutex.unlock();
						return;
					}
					else{
						readerPresenceMutex.unlock();
						/*	set writerPresence so no more reader can lock_shared	*/
						writerPresenceMutex.lock();
						writerPresence++;
						writerPresenceMutex.unlock();
						/*	wait for the last reader to notify	*/
						writeWaitQueueMutex.lock();
						this->writeWaitQueue->enqueue(pthread_self());
						writeWaitQueueMutex.unlock();
						waitSignal();
						/*	no more reader, we lock	*/
						return;
					}				
				}
				else{
					/*
						there are other writers, wait in queue to be notified	
						this also means there is absolutely no reader
					*/
					writerPresence++;
					writerPresenceMutex.unlock();
					/*	add this thread to queue	*/
					writeWaitQueueMutex.lock();
					this->writeWaitQueue->enqueue(pthread_self());
					writeWaitQueueMutex.unlock();
					/*	wait for signal from preceeded thread	*/
					waitSignal();
					/*	we've just been signaled from other thread, now we lock	*/				
					return;
				}
			}
	
			void lock_shared(){
				/* check if there is any pending writer	*/
				writerPresenceMutex.lock();
				//printf("lockshare with writerPresence %d\n", writerPresence);
				if (writerPresence == 0){
					/*	no writer, we can lock_shared	*/
					writerPresenceMutex.unlock();
					readerPresenceMutex.lock();
					readerPresence++;
					readerPresenceMutex.unlock();
					return;
				}
				else{
					/*	
						there is at least one writer has obtained the mutex or JUST WANTED TO enter the critical session
						we can no more allow reader to enter the queue, but after the last writer releases the mutex						
					*/					
					writerPresenceMutex.unlock();
				
					/*	wait here for the last writer to notify	*/					
					readWaitQueueMutex.lock();
					this->readWaitQueue->enqueue(pthread_self());
					readWaitQueueMutex.unlock();
					waitSignal();
				
					/*	notified, we can lock_shared	*/
					readerPresenceMutex.lock();
					readerPresence++;
					readerPresenceMutex.unlock();
				
					return;
				}
			}
	
			void unlock_shared(){
				readerPresenceMutex.lock();
				//printf("unlock shared with readerPresence %d\n", readerPresence);
				if (readerPresence == 0){
					/*	there is no lock_shared to be unlock_shared	*/			
					readerPresenceMutex.unlock();
					return;
				}
				else{
					readerPresence--;
					if (readerPresence == 0){
						readerPresenceMutex.unlock();
						/*	we are the last reader, notify the first writer (if any) to lock	*/
						writeWaitQueueMutex.lock();
						if (this->writeWaitQueue->notEmpty()){
							/*	this must be the first writer waiting	*/
							pthread_t tid;
							this->writeWaitQueue->peak(&tid);
							pthread_kill(tid, SVC_SHARED_MUTEX_SIGNAL);
							this->writeWaitQueue->dequeue();
							/*	job done, return	*/
							writeWaitQueueMutex.unlock();
							return;
						}
						else{
							writeWaitQueueMutex.unlock();
							return;
						}
					}
					else{
						readerPresenceMutex.unlock();
						return;
					}
				}
			}
	
			void unlock(){
				/*	check if there are other writer waiting	*/
				writerPresenceMutex.lock();
				//printf("unlock with writerPresence %d\n", writerPresence);
				if (writerPresence == 0){
					/*	no more lock to unlock	*/
					writerPresenceMutex.unlock();
					return;
				}
				else{
					writerPresence--;
					writerPresenceMutex.unlock();
					/*	notify the next writer if any	*/
					writeWaitQueueMutex.lock();
					if (this->writeWaitQueue->notEmpty()){
						/*	notify	*/
						pthread_t tid;
						this->writeWaitQueue->peak(&tid);
						pthread_kill(tid, SVC_SHARED_MUTEX_SIGNAL);
						this->writeWaitQueue->dequeue();
						writeWaitQueueMutex.unlock();
						return;
					}
					else{			
						writeWaitQueueMutex.unlock();		
						/*	no more writer, notify all readers	*/
				
						readWaitQueueMutex.lock();
						while (this->readWaitQueue->notEmpty()){
							pthread_t tid;
							this->readWaitQueue->peak(&tid);
							pthread_kill(tid, SVC_SHARED_MUTEX_SIGNAL);
							this->readWaitQueue->dequeue();
						}
						readWaitQueueMutex.unlock();
						return;
					}
				}
			}
	};

#endif
