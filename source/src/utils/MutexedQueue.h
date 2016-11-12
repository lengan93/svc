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
			pthread_t waitDataThread;
			
			pthread_mutexattr_t mutexAttr;
			pthread_condattr_t condAttr;
			pthread_mutex_t firstMutex;
			pthread_mutex_t lastMutex;
			pthread_mutex_t waitMutex;		
			pthread_cond_t waitCond;
						
			//--	waitData used in mutex lock, not need to lock again
			bool waitData(int timeout){
				int rs;
				pthread_mutex_lock(&this->waitMutex);
				//this->waitDataThread = pthread_self();
				//pthread_mutex_unlock(&this->waitMutex);
				if (timeout<0){
					//rs = waitSignal(QUEUE_DATA_SIGNAL);			
					rs = (pthread_cond_wait(&this->waitCond, &this->waitMutex));
				}
				else{				
					//rs = waitSignal(QUEUE_DATA_SIGNAL, timeout);
					struct timespec timeoutSpec;
					clock_gettime(CLOCK_REALTIME, &timeoutSpec);
					//-- add timeout to timeoutSpec
					uint32_t added = timeout*1000000 + timeoutSpec.tv_nsec; //-- nano secs
					timeoutSpec.tv_sec += added/1000000000;
					timeoutSpec.tv_nsec = added%1000000000;
					rs = pthread_cond_timedwait(&this->waitCond, &this->waitMutex, &timeoutSpec);
					/*if (rs!=0){
						printf("\npthread_cond_timedwait failed with error: %d", rs); fflush(stdout);
					}*/
				}
				//pthread_mutex_lock(&this->waitMutex);
				//this->waitDataThread = 0;
				pthread_mutex_unlock(&this->waitMutex);				
				return rs==0;
			}

		public:
	
			MutexedQueue(){
				this->beforeLastNode = NULL;
				this->lastNode = NULL;
				this->e = NULL;
				this->first = &this->e;
				this->last = &this->e;

				//this->waitDataThread = 0;
				pthread_mutexattr_init(&this->mutexAttr);
				pthread_mutex_init(&this->firstMutex, &this->mutexAttr);
				pthread_mutex_init(&this->lastMutex, &this->mutexAttr);
				pthread_mutex_init(&this->waitMutex, &this->mutexAttr);
				
				pthread_condattr_init(&this->condAttr);
				pthread_cond_init(&this->waitCond, &this->condAttr); 
			}
		
			~MutexedQueue(){
				while (this->notEmpty()){					
					this->dequeue();
				}
				//printf("\nthread 0x%08X removes node: 0x%08X", pthread_self(), (void*)this->lastNode); fflush(stdout);
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
				pthread_mutex_lock(&this->waitMutex);
				/*if (this->waitDataThread!=0){
					printf("\nthread 0x%08X notifies thread 0x%08X about data, *this->last = 0x%08X (new node), value(packet) = 0x%08X", pthread_self(), (void*)this->waitDataThread, (void*)node, (void*)data); fflush(stdout);
					//pthread_kill(this->waitDataThread, QUEUE_DATA_SIGNAL);
					
					//this->waitDataThread = 0;
				}
				else{
			    	printf("\nthread 0x%08X enqueues new node: 0x%08X with value(packet) 0x%08X", (void*)pthread_self(), (void*)node, (void*)data); fflush(stdout);
				}*/
				pthread_cond_signal(&this->waitCond);
				pthread_mutex_unlock(&this->waitMutex);
				pthread_mutex_unlock(&this->lastMutex);
			}
			
			T dequeueWait(int timeout){
				pthread_mutex_lock(&this->firstMutex);
				bool haveData = true;
				if ((*(this->first))==NULL){
					//printf("\nthread 0x%08X calls waitData, *this->first = 0x%08X", pthread_self(), (void*)(*(this->first))); fflush(stdout);		
					haveData = waitData(timeout);
				}
				if (haveData){
					//printf("\nthread 0x%08X haveData, dereferencing *this->first = 0x%08X ", (void*)pthread_self(), (void*)(*(this->first))); fflush(stdout);
					T retVal = (*(this->first))->data;
					//printf("\nthread 0x%08X got data 0x%08X", (void*)pthread_self(), (void*)(*(this->first))->data); fflush(stdout);
					this->beforeLastNode = this->lastNode;
					this->lastNode = *(this->first);		
					this->first = &((*(this->first))->next);
					//printf("\nthread 0x%08X removes node: 0x%08X", pthread_self(), (void*)this->beforeLastNode); fflush(stdout);
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
					this->lastNode = *(this->first);			
					this->first = &((*(this->first))->next);
					//printf("\nthread 0x%08X removes node: 0x%08X", (void*)pthread_self(), (void*)this->beforeLastNode); fflush(stdout);					
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
	
