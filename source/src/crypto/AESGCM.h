#ifndef  __TOM_AES-GCM__
#define __TOM_AES-GCM__

	#include "crypto-utils.h"
	
	
	class AESGCM{
	
		uint8_t* key;
		int keyLength;
		
		private:
		
		public:
			AESGCM(int keyLength);
			~AESGCM();
			void setKey(uint8_t* key);
			bool encrypt(const uint8_t* data, uint8_t* encrypted);
			bool decrypt(const uint8_t* encrypted, uint8_t* data);
	}


#endif
