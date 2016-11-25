/* 
	Author: Immort
	This queue is implemented to be generic and thread-safe
*/

#ifndef __SVC_QUEUE__
#define __SVC_QUEUE__

	#include <iostream>
	#include <pthread.h>
	#include <cstdint>
	
	#include "Node.h"

	using namespace std;

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
				if (timeout<0){		
					rs = pthread_cond_wait(&this->waitCond, &this->waitMutex);
				}
				else{				
					struct timespec timeoutSpec;
					clock_gettime(CLOCK_REALTIME, &timeoutSpec);
					//-- add timeout to timeoutSpec
					uint32_t addedSec = timeout/1000;
					uint32_t addedNsec = (timeout%1000)*1000000;
					if (addedNsec + timeoutSpec.tv_nsec >= 1000000000){
						timeoutSpec.tv_nsec = addedNsec + timeoutSpec.tv_nsec - 1000000000;
						addedSec +=1;
					}
					else{
						timeoutSpec.tv_nsec = addedNsec + timeoutSpec.tv_nsec;
					}
					timeoutSpec.tv_sec += addedSec;
					rs = pthread_cond_timedwait(&this->waitCond, &this->waitMutex, &timeoutSpec);
				}
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
				
				pthread_mutexattr_init(&this->mutexAttr);
				pthread_mutex_init(&this->firstMutex, &this->mutexAttr);
				pthread_mutex_init(&this->lastMutex, &this->mutexAttr);
				pthread_mutex_init(&this->waitMutex, &this->mutexAttr);
				
				pthread_condattr_init(&this->condAttr);
				pthread_cond_init(&this->waitCond, &this->condAttr); 
			}
		
			~MutexedQueue(){
				pthread_mutex_lock(&this->waitMutex);
				pthread_cond_signal(&this->waitCond);
				pthread_mutex_unlock(&this->waitMutex);
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
				pthread_mutex_lock(&this->waitMutex);
				pthread_cond_signal(&this->waitCond);
				pthread_mutex_unlock(&this->waitMutex);
				pthread_mutex_unlock(&this->lastMutex);
			}
			
			T dequeueWait(int timeout){
				pthread_mutex_lock(&this->firstMutex);
				bool haveData = false;
				bool waitDataCalled = false;
				if ((*(this->first))==NULL){
					waitDataCalled = true;
					haveData = waitData(timeout);
				}
				else{
					haveData = true;
				}
				if (haveData){
					//-- spurious wakeup might occur, need to check this->first again
					if((*(this->first)) != NULL){					
						T retVal = (*(this->first))->data;
						this->beforeLastNode = this->lastNode;
						this->lastNode = *(this->first);		
						this->first = &((*(this->first))->next);					
						delete this->beforeLastNode;
						pthread_mutex_unlock(&this->firstMutex);
						return retVal;
					}
					else{
						pthread_mutex_unlock(&this->firstMutex);
						return NULL;
					}
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
					delete this->beforeLastNode;
					pthread_mutex_unlock(&this->firstMutex);
				}
			}
			
			bool peak(T* data){
				pthread_mutex_lock(&this->firstMutex);
				if (*(this->first) == NULL){
					pthread_mutex_unlock(&this->firstMutex);
					return false;					
				}
				else{
					*data = (*(this->first))->data;
					pthread_mutex_unlock(&this->firstMutex);
					return true;
				}
			}
			
			bool peakWait(T* data, int timeout){
				pthread_mutex_lock(&this->firstMutex);
				bool haveData = true;
				if (*(this->first)==NULL){
					haveData = waitData(timeout);
				}
				if (haveData){
					*data = (*(this->first))->data;								
				}				
				pthread_mutex_unlock(&this->firstMutex);
				return haveData;
			}
	};

#endif
	
