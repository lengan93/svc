#ifndef __TOM_CRYPTO_UTILS__
#define __TOM_CRYPTO_UTILS__

		#include <fcntl.h>		//-- for O_RDONLY
		#include <cstdio>
		#include <fstream>
		#include <gmp.h>	
		#include <cstdlib>		
		#include <cstring>		//-- for 'memcpy'

	namespace crypto{	
		#define BIT(x) 0x01<<x	
		#define GET_BE32(a) ((((uint32_t) (a)[0]) << 24) | (((uint32_t) (a)[1]) << 16) | (((uint32_t) (a)[2]) << 8) | ((uint32_t) (a)[3]))
		#define PUT_BE32(a, val) do {                          \
					(a)[0] = (uint8_t) ((((uint32_t) (val)) >> 24) & 0xff);   \
					(a)[1] = (uint8_t) ((((uint32_t) (val)) >> 16) & 0xff);   \
					(a)[2] = (uint8_t) ((((uint32_t) (val)) >> 8) & 0xff);    \
					(a)[3] = (uint8_t) (((uint32_t) (val)) & 0xff);           \
			} while (0)

		static void generateRandomData(uint32_t length, void* data){
			std::ifstream urandom;
			urandom.open("/dev/urandom");
			if (urandom.is_open()){
				urandom.read((char*)data, length);
				urandom.close();
			}
		}

		static void generateRandomNumber(mpz_t* number, int securityParam){
			int byteLen = securityParam/8;
			uint8_t* randomData = (uint8_t*)malloc(byteLen);	
			generateRandomData(byteLen, randomData);
			for (int i=0;i<byteLen;i++){
				mpz_mul_ui(*number, *number, 256);
				mpz_add_ui(*number, *number, randomData[i]);
			}	
			free(randomData);
		}
	}
#endif // UTILS_H
