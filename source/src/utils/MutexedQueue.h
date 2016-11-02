/* 
	Author: Immort
	This queue is implemented to be generic and thread-safe
*/

#ifndef __SVC_QUEUE__
#define __SVC_QUEUE__

	#include "Node.h"
	#include "SharedMutex.h"
	#include "utils-functions.h"

	using namespace std;
	
	#define QUEUE_DATA_SIGNAL	SIGUSR2
	#define TIMEOUT_SIGNAL		SIGALRM

	template <class T>
	class MutexedQueue{	
		private:
			Node<T>* first;
			Node<T>* last;			
			int count;
			
			SharedMutex* countMutex;
			SharedMutex* firstMutex;
			SharedMutex* lastMutex;
			
			Queue<pthread_t>* waitDataThreads;
						
			//--	waitData used in mutex lock, not need to lock again
			bool waitData(int timeout){
				//printf("\n wait data called with timeout = %d", timeout);
				this->waitDataThreads->enqueue(pthread_self());
				if (timeout<0)
					return waitSignal(QUEUE_DATA_SIGNAL);
				else
					return waitSignal(QUEUE_DATA_SIGNAL, TIMEOUT_SIGNAL, timeout);
			}
			
			//--	signalThread used in mutex lock, not need to lock again
			void signalThread(){
				pthread_t thread;
				
				if (this->waitDataThreads->peak(&thread)){
					this->waitDataThreads->dequeue();
					pthread_kill(thread, QUEUE_DATA_SIGNAL);
				
				}		
			}
			
		public:
	
			MutexedQueue(){
				this->first = NULL;
				this->last = NULL;
				this->count = 0;
				countMutex = new SharedMutex();
				firstMutex = new SharedMutex();
				lastMutex = new SharedMutex();
				waitDataThreads = new Queue<pthread_t>();								
			}
		
			~MutexedQueue(){
				while (this->notEmpty()){
					delete this->dequeue();
				}
				delete this->waitDataThreads;
			}
		
			bool notEmpty(){			
				bool rs;
				this->countMutex->lock_shared();
				rs = count>0;
				this->countMutex->unlock_shared();
				return rs;
			}

			void enqueue(T data){
				Node<T>* element = new Node<T>();
				element->setData(data);
				element->setNext(NULL);
				
				this->lastMutex->lock();
				if (this->notEmpty()){					
					this->last->setNext(element);
					this->last = element;					
				}
				else{					
					this->first = element;
					this->last = element;									
					signalThread();
				}
				this->countMutex->lock();
				this->count++;
				this->countMutex->unlock();
				this->lastMutex->unlock();
			}
			
			T dequeueWait(int timeout){
				bool haveData = false;
				this->firstMutex->lock();
				if (!this->notEmpty()){
					//printf("\nnodata in queue, calling waitData"); fflush(stdout);
					haveData = waitData(timeout);
					//--	after waitData there must be data in queue, 'cause no other can perform dequeue
					//printf("\nafter calling waitdata, havedata = %d", haveData); fflush(stdout);
				}
				//--	not empty, have not to wait				
				if (haveData){
					Node<T>* tmp = this->first;
					this->first = tmp->getNext();																				
					this->countMutex->lock();
					this->count--;				
					this->countMutex->unlock();				
					this->firstMutex->unlock();
					return tmp->getData();
				}
				else{//else: waitData interrupted by other signals
					return NULL;
				}
			}
			
			T dequeue(){
				this->firstMutex->lock();
				if (this->notEmpty()){					
					Node<T>* tmp = this->first;
					this->first = tmp->getNext();					
					
					this->countMutex->lock();
					this->count--;				
					this->countMutex->unlock();
					
					this->firstMutex->unlock();
					return tmp->getData();										
				}
				else{
					this->firstMutex->unlock();
					return NULL;
				}
			}
			
			bool peak(T* data){
				if (this->notEmpty()){
					this->firstMutex->lock_shared();
					*data = this->first->getData();
					this->firstMutex->unlock_shared();
					return true;
				}
				else{
					return false;
				}
			}
	};

#endif
	
