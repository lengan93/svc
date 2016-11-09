/* 
	Author: Immort
	This queue is implemented to be generic and thread-safe
*/

#ifndef __SVC_QUEUE__
#define __SVC_QUEUE__

	#include "Node.h"
	#include "utils-functions.h"
	#include <pthread.h>

	using namespace std;
	
	#define QUEUE_DATA_SIGNAL	SIGUSR2

	template <class T>
	class MutexedQueue{	
		private:
			Node<T>* first;
			Node<T>* last;			
			int count;
			
			pthread_mutexattr_t mutexAttr;
			pthread_mutex_t countMutex;
			pthread_mutex_t firstMutex;
			pthread_mutex_t lastMutex;			
			pthread_t waitDataThread;
						
			//--	waitData used in mutex lock, not need to lock again
			bool waitData(int timeout){
				waitDataThread = pthread_self();
				if (timeout<0)
					return waitSignal(QUEUE_DATA_SIGNAL);
				else
					return waitSignal(QUEUE_DATA_SIGNAL, timeout);
			}
			
			//--	signalThread used in mutex lock, not need to lock again
			void signalThread(){
				if (this->waitDataThread!=0){
					pthread_kill(this->waitDataThread, QUEUE_DATA_SIGNAL);
					this->waitDataThread = 0;
				}
			}

		public:
	
			MutexedQueue(){
				this->first = NULL;
				this->last = NULL;
				this->count = 0;
				this->waitDataThread = 0;
				pthread_mutexattr_init(&this->mutexAttr);
				pthread_mutex_init(&this->countMutex, &this->mutexAttr);
				pthread_mutex_init(&this->firstMutex, &this->mutexAttr);
				pthread_mutex_init(&this->lastMutex, &this->mutexAttr);
				//printf("\nMutexedQueue created"); fflush(stdout);
			}
		
			~MutexedQueue(){
				while (this->notEmpty()){					
					this->dequeue();
				}
				//printf("\nMutexedQueue destructed"); fflush(stdout);
			}
			
			bool notEmpty(){
				bool rs;
				pthread_mutex_lock(&this->countMutex);
				rs = count>0;
				pthread_mutex_unlock(&this->countMutex);
				return rs;
			}			

			void enqueue(T data){
				//printf("\nenqueue: trying LOCK lastMutex"); fflush(stdout);										
				pthread_mutex_lock(&this->lastMutex);
				//printf("\nenqueue: lastMutex locked"); fflush(stdout);
				
				//printf("\nenqueue: trying LOCK countMutex"); fflush(stdout);
				pthread_mutex_lock(&this->countMutex);
				//printf("\nenqueue: countMutex locked"); fflush(stdout);
				Node<T>* element = new Node<T>();
				element->data = data;
				element->next = NULL;
				
				if (this->count > 0){
					this->last->next = element;
					this->last = element;
					this->count++;
					//printf("\nenqueue: trying UNLOCK countMutex"); fflush(stdout);
					pthread_mutex_unlock(&this->countMutex);
					//printf("\nenqueue: countMutex unlocked"); fflush(stdout);
					
					//printf("\nenqueue: trying UNLOCK lastMutex"); fflush(stdout);
					pthread_mutex_unlock(&this->lastMutex);
					//printf("\nenqueue: lastMutex unlocked"); fflush(stdout);
				}
				else{			
					this->first = element;
					this->last = element;
					this->count++;
					//printf("\nenqueue: trying UNLOCK countMutex"); fflush(stdout);
					pthread_mutex_unlock(&this->countMutex);
					//printf("\nenqueue: countMutex unlocked"); fflush(stdout);
					
					//printf("\nenqueue: trying UNLOCK lastMutex"); fflush(stdout);
					pthread_mutex_unlock(&this->lastMutex);
					//printf("\nenqueue: lastMutex unlocked"); fflush(stdout);
					signalThread();
				}
			}
			
			T dequeueWait(int timeout){
				//printf("\ndequeueWait: trying LOCK firstMutex"); fflush(stdout);
				pthread_mutex_lock(&this->firstMutex);
				//printf("\ndequeueWait: firstMutex locked"); fflush(stdout);
				
				//printf("\ndequeueWait: trying LOCK countMutex"); fflush(stdout);
				pthread_mutex_lock(&this->countMutex);
				//printf("\ndequeueWait: countMutex locked"); fflush(stdout);
				bool haveData = true;				
				if (this->count == 0){
					pthread_mutex_unlock(&this->countMutex);
					haveData = waitData(timeout);
				}
				else{
					pthread_mutex_unlock(&this->countMutex);
				}
				//--	not empty, have not to wait
				pthread_mutex_lock(&this->countMutex);
				if (haveData){
					Node<T>* tmp = this->first;
					T retVal = tmp->data;
					this->first = tmp->next;
					this->count--;
					//printf("\ndequeueWait: trying UNLOCK countMutex"); fflush(stdout);
					pthread_mutex_unlock(&this->countMutex);
					//printf("\ndequeueWait: countMutex unlocked"); fflush(stdout);
					
					//printf("\ndequeueWait: trying UNLOCK firstMutex"); fflush(stdout);
					pthread_mutex_unlock(&this->firstMutex);
					//printf("\ndequeueWait: firstMutex unlocked"); fflush(stdout);
					delete tmp;
					return retVal;
				}
				else{
					//-- waitData was interrupted by other signals
					//printf("\ndequeueWait: trying UNLOCK countMutex"); fflush(stdout);
					pthread_mutex_unlock(&this->countMutex);
					//printf("\ndequeueWait: countMutex unlocked"); fflush(stdout);
					
					//printf("\ndequeueWait: trying UNLOCK firstMutex"); fflush(stdout);
					pthread_mutex_unlock(&this->firstMutex);
					//printf("\ndequeueWait: firstMutex unlocked"); fflush(stdout);
					return NULL;
				}
			}
			
			void dequeue(){
				pthread_mutex_lock(&this->firstMutex);
				pthread_mutex_lock(&this->countMutex);
				if (this->count>0){
					Node<T>* tmp = this->first;
					this->first = tmp->next;
					this->count--;
					pthread_mutex_unlock(&this->countMutex);
					pthread_mutex_unlock(&this->firstMutex);
					delete tmp;
				}
				else{
					pthread_mutex_unlock(&this->countMutex);
					pthread_mutex_unlock(&this->firstMutex);	
				}
			}
			
			bool peak(T* data){
				pthread_mutex_lock(&this->countMutex);
				if (this->count>0){
					pthread_mutex_lock(&this->firstMutex);
					*data = this->first->data;
					pthread_mutex_unlock(&this->firstMutex);
					pthread_mutex_unlock(&this->countMutex);
					return true;
				}
				else{
					pthread_mutex_unlock(&this->countMutex);
					return false;
				}
			}						
	};

#endif
	
