#ifndef	__TOM_NODE__
#define __TOM_NODE__

	template <class T>
	class Node{
		private:
			T data;
			Node* next;
		public:
			void setData(T data){
				this->data = data;
			}
			void setNext(Node* next){
				this->next = next;
			}
			T getData(){
				return this->data;
			}
			Node* getNext(){
				return this->next;
			}
	};
	
#endif
