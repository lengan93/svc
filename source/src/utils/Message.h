#ifndef __TOM_MESSAGE__
#define	__TOM_MESSAGE__

	class Message{
		public:
			uint8_t* data;
			size_t len;
			
			Message(const uint8_t* data, size_t len);			
			~Message();	
	};
	
	Message::Message(const uint8_t* data, size_t len){
		this->data = (uint8_t*)malloc(SVC_DEFAULT_BUFSIZ);
		this->len = len;
		memcpy(this->data, data, this->len);
	}

	Message::~Message(){
		delete data;		
	}

#endif
