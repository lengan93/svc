#include "crypto-utils.h"
#include <cstring>

using namespace std;

string hexToString(uint8_t* data, size_t len){
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
	for (int i=0;i<hexString.size()/2;i+=2){
		c1 = hexString[i];
		if (c1>='A' && c1<='F')
			c1-= 55;
		else if (c1>='a' && c1<='f')
			c1-= 87;
		else
			c1-= 48;
		
		c2 = hexString[i+1];
		if (c2>='A' && c2<='F')
			c2-= 55;
		else if (c2>='a' && c2<='f')
			c2-= 87;
		else
			c2-= 48;
		data[i] = c1<<4 + c2;
	}
	return hexString.size()/2;
}
