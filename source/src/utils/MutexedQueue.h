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

	template <class T>
	class MutexedQueue{	
		private:
			Node<T>* first;
			Node<T>* last;			
			int count;
			
			SharedMutex* countMutex;
			SharedMutex* firstMutex;
			SharedMutex* lastMutex;
			
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
				countMutex = new SharedMutex();
				firstMutex = new SharedMutex();
				lastMutex = new SharedMutex();
			}
		
			~MutexedQueue(){
				while (this->notEmpty()){					
					this->dequeue();
				}
				delete this->countMutex;
				delete this->firstMutex;
				delete this->lastMutex;
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
					this->countMutex->lock();
					this->count++;
					this->countMutex->unlock();
					this->lastMutex->unlock();
				}
				else{			
					this->first = element;
					this->last = element;
					this->countMutex->lock();
					this->count++;
					this->countMutex->unlock();
					this->lastMutex->unlock();
					signalThread();
				}				
			}
			
			T dequeueWait(int timeout){
				bool haveData = true;
				this->firstMutex->lock();
				if (!this->notEmpty()){
					haveData = waitData(timeout);
				}
				//--	not empty, have not to wait
				if (haveData){
					//printf("\ndequeueWait has data, count = %d, this->first = 0x%08X", this->count, (void*)this->first); fflush(stdout);
					Node<T>* tmp = this->first;
					this->first = tmp->getNext();
					this->countMutex->lock();
					this->count--;
					this->countMutex->unlock();
					this->firstMutex->unlock();
					return tmp->getData();
				}
				else{
					//-- waitData was interrupted by other signals
					this->firstMutex->unlock();
					return NULL;
				}
			}
			
			void dequeue(){
				this->firstMutex->lock();
				if (this->notEmpty()){					
					Node<T>* tmp = this->first;
					this->first = tmp->getNext();					
					this->countMutex->lock();
					this->count--;
					this->countMutex->unlock();					
					this->firstMutex->unlock();
					delete tmp;
				}
				else{
					this->firstMutex->unlock();					
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
	
