#ifndef __TOM_QUEUE__
#define __TOM_QUEUE__
	
	#include "Node.h"
	#include <cstddef>

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
				element->data = data;
				element->next = NULL;
				
				if (this->notEmpty()){	
					this->last->next=element;
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
					this->first = tmp->next;
					this->count--;
					delete tmp;
				}
			}
		
			bool peak(T* data){			
				if (this->notEmpty()){
					*data = this->first->data;				
					return true;
				}
				else{
					return false;
				}
			}
	};

#endif
