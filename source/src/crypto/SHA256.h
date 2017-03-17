#ifndef __SHA256__
#define __SHA256__

	#include <cstdint>
	#include <cstring>
	
	class SHA256{		
	 
		const static uint32_t sha256_k[];
		static const uint8_t SHA224_256_BLOCK_SIZE = (512/8);
		
		
		uint32_t m_tot_len;
		uint32_t m_len;
		uint8_t  m_block[2*SHA224_256_BLOCK_SIZE];
		uint32_t m_h[8];
		
		void init();
		void transform(const unsigned char *message, uint32_t block_nb);
		void update(const uint8_t* message, uint32_t len);
		void final(uint8_t* digest);
				
		public:
			static const unsigned int DIGEST_SIZE = (256 / 8);
			SHA256();
			~SHA256();			
			void hash(const void* input, uint16_t inputLength, uint8_t* output);
	};	 
	 
	#define SHA2_SHFR(x, n)    (x >> n)
	#define SHA2_ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
	#define SHA2_ROTL(x, n)   ((x << n) | (x >> ((sizeof(x) << 3) - n)))
	#define SHA2_CH(x, y, z)  ((x & y) ^ (~x & z))
	#define SHA2_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
	#define SHA256_F1(x) (SHA2_ROTR(x,  2) ^ SHA2_ROTR(x, 13) ^ SHA2_ROTR(x, 22))
	#define SHA256_F2(x) (SHA2_ROTR(x,  6) ^ SHA2_ROTR(x, 11) ^ SHA2_ROTR(x, 25))
	#define SHA256_F3(x) (SHA2_ROTR(x,  7) ^ SHA2_ROTR(x, 18) ^ SHA2_SHFR(x,  3))
	#define SHA256_F4(x) (SHA2_ROTR(x, 17) ^ SHA2_ROTR(x, 19) ^ SHA2_SHFR(x, 10))
	#define SHA2_UNPACK32(x, str)                 \
	{                                             \
		*((str) + 3) = (uint8_t) ((x)      );       \
		*((str) + 2) = (uint8_t) ((x) >>  8);       \
		*((str) + 1) = (uint8_t) ((x) >> 16);       \
		*((str) + 0) = (uint8_t) ((x) >> 24);       \
	}
	#define SHA2_PACK32(str, x)                   \
	{                                             \
		*(x) =   ((uint32_t) *((str) + 3)      )    \
			   | ((uint32_t) *((str) + 2) <<  8)    \
			   | ((uint32_t) *((str) + 1) << 16)    \
			   | ((uint32_t) *((str) + 0) << 24);   \
	}
	
#endif
