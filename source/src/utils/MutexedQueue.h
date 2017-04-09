/* 
	Author: Immort
	This queue is implemented to be generic and thread-safe
*/

#ifndef __SVC_QUEUE__
#define __SVC_QUEUE__

	#include <thread>
	#include <mutex>
	#include <condition_variable>

	#include "Node.h"

	template <class T>
	class MutexedQueue{	
		private:
			Node<T>** first;
			Node<T>** last;	
			Node<T>* e;		
			Node<T>* lastNode;
			Node<T>* beforeLastNode;
			
			std::mutex firstMutex;
			std::mutex lastMutex;
			std::mutex waitMutex;		
			std::condition_variable waitCond;
			volatile bool working;
			bool haveData;

			bool waitData(int timeout){
				bool rs;
				std::cv_status cv;
				std::unique_lock<std::mutex> uLock(waitMutex); //-- this will attemp to lock the mutex
				this->haveData = false;
				if (timeout<0){
					//-- spurious awake may occur but we had "haveData" to check this
					waitCond.wait(uLock, [this]{return !this->working || this->haveData;});
					rs = this->haveData;
				}
				else{
					cv = waitCond.wait_for(uLock, std::chrono::milliseconds(timeout));
					rs = (cv == std::cv_status::no_timeout);
				}
				this->waitMutex.unlock();
				return rs;
			}

		public:
	
			MutexedQueue(){
				this->beforeLastNode = NULL;
				this->lastNode = NULL;
				this->e = NULL;
				this->first = &this->e;
				this->last = &this->e;
				this->working = true;
			}

			void close(){
				this->working = false;
				waitCond.notify_all();
			}

			bool isOpen(){
				return this->working;
			}
		
			~MutexedQueue(){
				if (this->working){
					this->close();
				}
				while (this->notEmpty()){					
					this->dequeue();
				}
				delete this->lastNode;
			}
			
			bool notEmpty(){
				bool rs;
				this->firstMutex.lock();
				rs = (*(this->first))!=NULL;
				this->firstMutex.unlock();
				return rs;
			}			

			void enqueue(T data){
				this->lastMutex.lock();		
				Node<T>* node = new Node<T>();
				node->data = data;
				node->next = NULL;
				(*(this->last)) = node;
				this->last = &(node->next);
				this->haveData = true;
				this->waitCond.notify_all();
				this->lastMutex.unlock();
			}
			
			T dequeueWait(int timeout){
				this->firstMutex.lock();
				bool isData = false;
				if ((*(this->first))==NULL){
					isData = waitData(timeout);
				}
				else{
					isData = true;
				}
				if (isData){
					//-- spurious wakeup might occur, but waitData handled it
					// if((*(this->first)) != NULL){					
						T retVal = (*(this->first))->data;
						this->beforeLastNode = this->lastNode;
						this->lastNode = *(this->first);		
						this->first = &((*(this->first))->next);					
						delete this->beforeLastNode;
						this->firstMutex.unlock();
						return retVal;
					// }
					// else{
					// 	this->firstMutex.unlock();
					// 	return NULL;
					// }
				}
				else{
					//-- waitData was interrupted by other signals
					this->firstMutex.unlock();
					return NULL;
				}				
			}
			
			void dequeue(){
				this->firstMutex.lock();				
				if (*(this->first)==NULL){
					this->firstMutex.unlock();
				}
				else{					
					this->beforeLastNode = this->lastNode;
					this->lastNode = *(this->first);			
					this->first = &((*(this->first))->next);					
					delete this->beforeLastNode;
					this->firstMutex.unlock();
				}
			}
			
			bool peak(T* data){
				this->firstMutex.lock();
				if (*(this->first) == NULL){
					this->firstMutex.unlock();
					return false;					
				}
				else{
					*data = (*(this->first))->data;
					this->firstMutex.unlock();
					return true;
				}
			}
			
			bool peakWait(T* data, int timeout){
				this->firstMutex.lock();
				bool isData = false;
				if (*(this->first)==NULL){
					isData = waitData(timeout);
				}
				if (isData){
					// if ((*(this->first)) != NULL)
						*data = (*(this->first))->data;								
				}				
				this->firstMutex.unlock();
				return isData;
			}
	};

#endif
	
