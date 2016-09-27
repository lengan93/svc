#ifndef  __TOM_AES-GCM__
#define __TOM_AES-GCM__

	#include "crypto-utils.h"
	
	#define ERROR_KEYLENGTH_NOT_SUPPORTED "Keylength is not supported"
	
	#define BLOCK_SIZE 128
		
	enum SecurityParameter : int {
		SECU_128 = 128,
		SECU_120 = 120,
		SECU_112 = 112,
		SECU_104 = 104,
		SECU_96 = 96
	};
	
	
	class AESGCM{
					
		uint8_t* key;
		int keyLength;
		enum SecurityParameter secuParam;
		
		private:
			static void mulBlock();
		
		public:
			
			//--	SECURITY PARAMETERS			
			AESGCM(int keyLength);
			~AESGCM();
			void setKey(const uint8_t* key, enum SecurityParameter secuParam);
			bool encrypt(const uint8_t* data, uint8_t* encrypted);
			bool decrypt(const uint8_t* encrypted, uint8_t* data);
	};


#endif
