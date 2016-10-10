#ifndef  __TOM_AES_GCM__
#define __TOM_AES_GCM__

	#include "AES256.h"
	
	#define ERROR_DATALENGTH_NOT_SUPPORTED "Length not supported"
	//#undef BLOCK_SIZE
	//#define BLOCK_SIZE 1
	
	#define BIT(x) 0x01<<x	
	#define GET_BE32(a) ((((uint32_t) (a)[0]) << 24) | (((uint32_t) (a)[1]) << 16) | (((uint32_t) (a)[2]) << 8) | ((uint32_t) (a)[3]))
	#define PUT_BE32(a, val) do {                          \
                (a)[0] = (uint8_t) ((((uint32_t) (val)) >> 24) & 0xff);   \
                (a)[1] = (uint8_t) ((((uint32_t) (val)) >> 16) & 0xff);   \
                (a)[2] = (uint8_t) ((((uint32_t) (val)) >> 8) & 0xff);    \
                (a)[3] = (uint8_t) (((uint32_t) (val)) & 0xff);           \
        } while (0)
	
	enum SecurityParameter : int {
		SECU_128 = 128,
		SECU_120 = 120,
		SECU_112 = 112,
		SECU_104 = 104,
		SECU_96 = 96
	};
	
	class AESGCM{

		AES256* aes256;		
		uint8_t* hashSubKey;		
		enum SecurityParameter secuParam;

		private:
			
			//--	shift the whole array to the right by 1 bit
			void bitRightShiftBlock(uint8_t* block);
			//--	return Z = X^Y
			void xorBlock(uint8_t* blockZ, const uint8_t* blockX, const uint8_t* blockY);
			//--	return Z = X*Y
			bool mulBlock(uint8_t* blockZ, const uint8_t* blockX, const uint8_t* blockY);
			//--	inc and dec
			void inc32(uint8_t* block);
			void dec32(uint8_t* block);
			
			//--	return gHash(X) under hashSubKey			
			bool gHash(const uint8_t* data, uint32_t dataLen, uint8_t** hash);
			//--	GCTR
			void gCTR(const uint8_t* icb, const uint8_t* xstr, uint8_t* ystr, uint32_t strLen);
		
		public:
			//--	SECURITY PARAMETERS	
			AESGCM(const uint8_t* key, enum SecurityParameter secuParam);
			~AESGCM();			
			bool encrypt(const uint8_t* iv, uint32_t ivLen, const uint8_t* data, uint32_t dataLen, const uint8_t* aad, uint32_t aadLen, uint8_t** encrypted, uint32_t* encryptedLen, uint8_t** tag, uint32_t* tagLen);
			bool decrypt(const uint8_t* encrypted, const size_t* encryptedLen, uint8_t* data, size_t* dataLen);
	};

#endif
