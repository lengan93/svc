#include "crypto-utils.h"
#include <cstring>

#include <iostream>

using namespace std;

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
	mpz_init(*number);
	int byteLen = securityParam/8;
	uint8_t randomData[byteLen];	
	generateRandomData(byteLen, randomData);
	for (int i=0;i<byteLen;i++){
		mpz_mul_ui(*number, *number, 256);		
		mpz_add_ui(*number, *number, randomData[i]);
	}
}

string hexToString(const uint8_t* data, uint32_t len){
	char buffer[len*2+1];
	uint8_t b;
	uint8_t c1;
	uint8_t c2;
	for (int i=0;i<len;i++){
		b = data[i];
		c1 = (b&0xF0)>>4;
		c2 = (b&0x0F);		
		buffer[2*i] = c1<10? (c1 + 48) : (c1 + 55);
		buffer[2*i+1] = c2<10? (c2 + 48) : (c2 + 55);
	}
	buffer[len*2+1] = '\0';
	return string(buffer);
}

uint32_t stringToHex(const string& hexString, uint8_t** data){
	
	if (hexString.size()>0){
		*data = (uint8_t*)malloc(hexString.size()/2);
		uint8_t c1;
		uint8_t c2;
		
		for (int i=0;i<hexString.size();i+=2){
			//-- extract first char
			c1 = hexString[i];
			if (c1>='A' && c1<='F')
				c1-= 55;
			else if (c1>='a' && c1<='f')
				c1-= 87;
			else
				c1-= 48;
			//-- extract second char
			c2 = hexString[i+1];
			if (c2>='A' && c2<='F')
				c2-= 55;
			else if (c2>='a' && c2<='f')
				c2-= 87;
			else
				c2-= 48;
			//-- calculate value
			(*data)[i/2] = (uint8_t)(c1*16 + c2);
		}
		return hexString.size()/2;
	}
	else{
		return 0;
	}
}
