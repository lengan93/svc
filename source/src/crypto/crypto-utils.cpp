#include "crypto-utils.h"

void generateRandomData(uint32_t length, uint8_t* data){
	uint32_t readByte = 0;
	int urandom = open("/dev/urandom", O_RDONLY);
	
	while (readByte < length){
		ssize_t result = read(urandom, data+readByte, length-readByte);
		if (result>0){
			readByte += result;
		}
	}
	close(urandom);
}

void generateRandomNumber(mpz_t* number, int securityParam){
	int byteLen = securityParam/8;
	uint8_t* randomData = (uint8_t*)malloc(byteLen);	
	generateRandomData(byteLen, randomData);
	for (int i=0;i<byteLen;i++){
		mpz_mul_ui(*number, *number, 256);
		mpz_add_ui(*number, *number, randomData[i]);
	}	
	free(randomData);
}
