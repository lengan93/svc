#ifndef __TOM_MESSAGE__
#define	__TOM_MESSAGE__
	
	#include <cstdint>
	#include <cstdlib>
	#include <cstring>
	
	#define DEFAULT_BUFFER_SIZE 65536

	class Message{
		public:
			uint8_t* data;
			uint32_t len;
			
			Message(uint32_t len){
				this->data = (uint8_t*)malloc(DEFAULT_BUFFER_SIZE);
				this->len = len;
				memset(this->data, 0, len);
			}
			
			Message(const uint8_t* data, uint32_t len){
				this->data = (uint8_t*)malloc(DEFAULT_BUFFER_SIZE);
				this->len = len;
				memcpy(this->data, data, len);
			}	
			~Message(){
				free(data);
			}
	};

#endif
