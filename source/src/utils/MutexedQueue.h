/* 
	Author: Immort
	This queue is implemented to be generic and thread-safe
*/

#ifndef __SVC_QUEUE__
#define __SVC_QUEUE__

	#include "Node.h"
	#include "utils-functions.h"

	using namespace std;
	
	#define QUEUE_DATA_SIGNAL	SIGUSR2

	template <class T>
	class MutexedQueue{	
		private:
			Node<T>** first;
			Node<T>** last;			
			Node<T>* lastNode;
			Node<T>* beforeLastNode;
			
			pthread_mutexattr_t mutexAttr;

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
				this->beforeLastNode = NULL;
				this->lastNode = NULL;
				this->first = &this->lastNode;
				this->last = &this->lastNode;

				this->waitDataThread = 0;
				pthread_mutexattr_init(&this->mutexAttr);
				pthread_mutex_init(&this->firstMutex, &this->mutexAttr);
				pthread_mutex_init(&this->lastMutex, &this->mutexAttr);
			}
		
			~MutexedQueue(){
				while (this->notEmpty()){					
					this->dequeue();
				}
				delete this->lastNode;
			}
			
			bool notEmpty(){
				bool rs;
				pthread_mutex_lock(&this->firstMutex);
				rs = (*(this->first))!=NULL;
				pthread_mutex_unlock(&this->firstMutex);
				return rs;
			}			

			void enqueue(T data){
				pthread_mutex_lock(&this->lastMutex);				
				(*(this->last)) = new Node<T>();
				(*(this->last))->data = data;
				(*(this->last))->next = NULL;
				this->last = &((*(this->last))->next);
				pthread_mutex_unlock(&this->lastMutex);
				signalThread();
			}
			
			T dequeueWait(int timeout){
				pthread_mutex_lock(&this->firstMutex);
				bool haveData = true;
				if ((*(this->first))==NULL){				
					haveData = waitData(timeout);
				}				
				if (haveData){
					T retVal = (*(this->first))->data;
					delete this->beforeLastNode;
					this->beforeLastNode = this->lastNode;
					this->lastNode = *(this->first);		
					this->first = &((*(this->first))->next);
					pthread_mutex_unlock(&this->firstMutex);
					return retVal;
				}
				else{
					//-- waitData was interrupted by other signals
					pthread_mutex_unlock(&this->firstMutex);
					return NULL;
				}
			}
			
			void dequeue(){
				pthread_mutex_lock(&this->firstMutex);				
				if (*(this->first)==NULL){
					pthread_mutex_unlock(&this->firstMutex);
				}
				else{
					delete this->beforeLastNode;
					this->beforeLastNode = this->lastNode;
					this->lastNode = (*(this->first));			
					this->first = &((*(this->first))->next);
					pthread_mutex_unlock(&this->firstMutex);
				}
			}
			
			bool peak(T* data){
				pthread_mutex_lock(&this->firstMutex);
				if ((*(this->first)) == NULL){
					pthread_mutex_unlock(&this->countMutex);
					return false;					
				}
				else{
					*data = (*(this->first))->data;
					pthread_mutex_unlock(&this->firstMutex);
					return true;
				}
			}						
	};

#endif
	
