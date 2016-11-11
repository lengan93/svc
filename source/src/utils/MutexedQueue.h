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
			Node<T>* e;		
			Node<T>* lastNode;
			Node<T>* beforeLastNode;
			
			pthread_mutexattr_t mutexAttr;

			pthread_mutex_t firstMutex;
			pthread_mutex_t lastMutex;			
			pthread_t waitDataThread;
						
			//--	waitData used in mutex lock, not need to lock again
			bool waitData(int timeout){
				bool rs;
				this->waitDataThread = pthread_self();
				if (timeout<0){
					rs = waitSignal(QUEUE_DATA_SIGNAL);					
				}
				else{				
					rs = waitSignal(QUEUE_DATA_SIGNAL, timeout);
				}
				if (!rs) this->waitDataThread = 0;
				return rs;
			}

		public:
	
			MutexedQueue(){
				this->beforeLastNode = NULL;
				this->lastNode = NULL;
				this->e = NULL;
				this->first = &this->e;
				this->last = &this->e;

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
				Node<T>* node = new Node<T>();
				node->data = data;
				node->next = NULL;
				(*(this->last)) = node;
				this->last = &(node->next);				
				if (this->waitDataThread!=0){
					//printf("\nthread 0x%08X notifies thread 0x%08X about data, *this->last = 0x%08X (new node)", (void*)pthread_self(), (void*)this->waitDataThread, (void*)node); fflush(stdout);
					pthread_kill(this->waitDataThread, QUEUE_DATA_SIGNAL);
					this->waitDataThread = 0;
				}
				//else{
					//printf("\nthread 0x%08X enqueues new node: 0x%08X", (void*)node); fflush(stdout);
				//}
				pthread_mutex_unlock(&this->lastMutex);
			}
			
			T dequeueWait(int timeout){
				pthread_mutex_lock(&this->firstMutex);
				bool haveData = true;
				if ((*(this->first))==NULL){
					//printf("\nthread 0x%08X calls waitData, *this->first = 0x%08X", (void*)pthread_self(), (void*)(*(this->first))); fflush(stdout);		
					haveData = waitData(timeout);
				}				
				if (haveData){
					//printf("\nthread 0x%08X haveData, *this->first = 0x%08X", (void*)pthread_self(), (void*)(*(this->first))); fflush(stdout);
					T retVal = (*(this->first))->data;					
					this->beforeLastNode = this->lastNode;
					this->lastNode = *(this->first);		
					this->first = &((*(this->first))->next);
					delete this->beforeLastNode;
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
					this->beforeLastNode = this->lastNode;
					this->lastNode = (*(this->first));			
					this->first = &((*(this->first))->next);
					delete this->beforeLastNode;
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
	
