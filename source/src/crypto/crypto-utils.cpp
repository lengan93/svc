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

string hexToString(const uint8_t* data, uint32_t len){
	string rs = "";
	uint8_t b;
	for (int i=0;i<len;i++){
		b = data[i];
		rs += ((b&0xF0)>>4)<10? ((b&0xF0)>>4) + 48 : ((b&0xF0)>>4) + 55;
		rs += (b&0x0F)<10? b&0xF0 + 48 : b&0x0F + 55;
	}
	return rs;
}

int stringToHex(const string& hexString, uint8_t* data){
	uint8_t c1;
	uint8_t c2;
	//cout<<"String to hex:"<<endl;
	for (int i=0;i<hexString.size();i+=2){
		c1 = hexString[i];
		//cout<<"c1="<<c1<<endl;
		if (c1>='A' && c1<='F')
			c1-= 55;
		else if (c1>='a' && c1<='f')
			c1-= 87;
		else
			c1-= 48;
		
		c2 = hexString[i+1];
		//cout<<"c2="<<c2<<endl;
		if (c2>='A' && c2<='F')
			c2-= 55;
		else if (c2>='a' && c2<='f')
			c2-= 87;
		else
			c2-= 48;
		data[i/2] = (uint8_t)(c1*16 + c2);
		//printf("data %02x\n", data[i]);
	}
	return hexString.size()/2;
}
