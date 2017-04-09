#ifndef __CRYPTO_UTILS__
#define __CRYPTO_UTILS__

	#include <cstdio>
	#include <fstream>
	#include <gmp.h>	
	#include <cstdlib>		
	#include <cstring>		//-- for 'memcpy'

	namespace crypto{

		

		static void generateRandomData(uint32_t length, void* data){
			std::ifstream urandom;
			#ifdef _WIN32
			#else
				urandom.open("/dev/urandom");
				if (urandom.is_open()){
					urandom.read((char*)data, length);
					urandom.close();
				}
			#endif
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
#endif
