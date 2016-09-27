#include "AESGCM.h"

AESGCM::AESGCM(int keyLength){	
	
	if (keyLength<=0 || keyLength%128!=0){
		throw ERROR_KEYLENGTH_NOT_SUPPORTED;
	}
	this->keyLength = keyLength;
	this->key = (uint8_t*)malloc(keyLength>>3);		
}

void AESGCM::setKey(const uint8_t* key, enum SecurityParameter secuParam){
	memcpy(this->key, key, this->keyLength);
	this->secuParam = secuParam;
}

AESGCM::~AEGGCM(){
	//--	securely remove the key by setting its value to 0
	memset(this->key, 0, this->keyLength);
	delete this->key;
}

