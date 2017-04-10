#ifndef  __TOM_AES_GCM__
#define __TOM_AES_GCM__

	#include "AES256.h"

	#define BIT(x) 0x01<<x	
	#define GET_BE32(a) ((((uint32_t) (a)[0]) << 24) | (((uint32_t) (a)[1]) << 16) | (((uint32_t) (a)[2]) << 8) | ((uint32_t) (a)[3]))
	#define PUT_BE32(a, val) do {                          \
				(a)[0] = (uint8_t) ((((uint32_t) (val)) >> 24) & 0xff);   \
				(a)[1] = (uint8_t) ((((uint32_t) (val)) >> 16) & 0xff);   \
				(a)[2] = (uint8_t) ((((uint32_t) (val)) >> 8) & 0xff);    \
				(a)[3] = (uint8_t) (((uint32_t) (val)) & 0xff);           \
		} while (0)
	
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
						
			inline void prepBlockJ(const void* iv, uint32_t ivLen);
			inline void calcBlockS(const void* aad, uint32_t aadLen, const void* encrypted, uint32_t encryptedLen);
			void gHash(uint8_t* hash, const uint8_t* data, uint32_t dataLen);
			void gCTR(void* ydata, const uint8_t* icb, const void* xdata, uint32_t strLen);
		
		public:
			//--	SECURITY PARAMETERS
			AESGCM(const uint8_t* key, enum SecurityParameter secuParam);
			~AESGCM();
			void encrypt(const void* iv, const uint16_t ivLen, const void* data, const uint32_t dataLen, const void* aad, const uint16_t aadLen, uint8_t** encrypted, uint32_t* encryptedLen, uint8_t** tag, uint16_t* tagLen);
			bool decrypt(const void* iv, const uint16_t ivLen, const void* encrypted, const uint32_t encryptedLen, const void* aad, const uint16_t aadLen, const void* tag, uint16_t tagLen, uint8_t** data, uint32_t* dataLen);
	};

#endif
