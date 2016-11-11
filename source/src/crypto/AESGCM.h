#ifndef  __TOM_AES_GCM__
#define __TOM_AES_GCM__

	#include "AES256.h"
	
	#define ERROR_DATALENGTH_NOT_SUPPORTED "Length not supported"
	
	enum SecurityParameter : uint8_t {
		SECU_128 = 128,
		SECU_120 = 120,
		SECU_112 = 112,
		SECU_104 = 104,
		SECU_96 = 96
	};
	
	class AESGCM{

		//--	block chiffer
		AES256* aes256;
		//--	prefedined blocks
		uint8_t hashSubKey[BLOCK_SIZE];
		uint8_t blockZero[BLOCK_SIZE];
		uint8_t blockJ[BLOCK_SIZE];
		uint8_t blockS[BLOCK_SIZE];
		
		enum SecurityParameter secuParam;

		private:	
			void bitRightShiftBlock(uint8_t* block);			
			void xorBlock(uint8_t* blockZ, const uint8_t* blockX, const uint8_t* blockY);			
			void mulBlock(uint8_t* blockZ, const uint8_t* blockX, const uint8_t* blockY);			
			void inc32(uint8_t* block);
			void dec32(uint8_t* block);
						
			inline void prepBlockJ(const uint8_t* iv, uint32_t ivLen);
			inline void calcBlockS(const uint8_t* aad, uint32_t aadLen, const uint8_t* encrypted, uint32_t encryptedLen);
			void gHash(uint8_t* hash, const uint8_t* data, uint32_t dataLen);
			void gCTR(uint8_t* ystr, const uint8_t* icb, const uint8_t* xstr, uint32_t strLen);
		
		public:
			//--	SECURITY PARAMETERS
			AESGCM(const uint8_t* key, enum SecurityParameter secuParam);
			~AESGCM();
			void encrypt(const uint8_t* iv, const uint32_t ivLen, const uint8_t* data, const uint32_t dataLen, const uint8_t* aad, const uint32_t aadLen, uint8_t** encrypted, uint32_t* encryptedLen, uint8_t** tag, uint32_t* tagLen);
			bool decrypt(const uint8_t* iv, const uint32_t ivLen, const uint8_t* encrypted, const uint32_t encryptedLen, const uint8_t* aad, const uint32_t aadLen, const uint8_t* tag, uint32_t tagLen, uint8_t** data, uint32_t* dataLen);
	};

#endif
