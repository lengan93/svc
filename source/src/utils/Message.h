#ifndef __TOM_MESSAGE__
#define	__TOM_MESSAGE__
	
	#include <cstdint>
	#include <cstdlib>
	#include <cstring>
	
	#define DEFAULT_BUFFER_SIZE 65536

	class Message{
		public:
			uint8_t* data;
			size_t len;
			
			Message(const uint8_t* data, size_t len);			
			~Message();	
	};
	
	Message::Message(const uint8_t* data, size_t len){
		this->data = (uint8_t*)malloc(DEFAULT_BUFFER_SIZE);
		this->len = len;
		memcpy(this->data, data, this->len);
	}

	Message::~Message(){
		delete data;		
	}

#endif
