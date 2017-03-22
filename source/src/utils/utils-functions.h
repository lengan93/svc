#ifndef __TOM_UTILS_FUNCTIONS__
#define __TOM_UTILS_FUNCTIONS__

	#include <cstdio>		//-- for 'printf'
	#include <iostream>
	#include <fstream>
	using namespace std;

	//--	print a buffer in HEX
	static inline void printBuffer(const uint8_t* data, size_t len){
		for (int i=0;i<len;i++){
			printf("%02x ", data[i]);
		}
		printf("\n");
	}
	
	static inline void printBitString(const uint8_t* data, size_t len){
		for (int i=0;i<len;i++){
			uint8_t b = data[i];
			for (int j=7;j>=0;j--){
				printf("%d", ((b&(0x01<<j))>>j));				
			}
		}
	}

	inline void logPacket(ofstream* file, uint32_t seq, uint8_t* data, size_t len) {
		static char gap[10] = {0};
		gap[0] = 0x10;
		gap[9] = 0x01;
		file->write((char*)&seq, 4);
		file->write((char*)data, len);
		file->write(gap, 10);
	}
	
#endif
