#include "AESGCM.h"

//--	private class methods			--//

void AESGCM xorBlock(uint8_t* blockZ, const uint8_t* blockX, const uint8_t* blockY){
	for (int i=0;i<BLOCK_BYTESIZE; i++){
		blockZ[i] = blockX[i]^blockY[i];
	}
}

void AESGCM::bitRightShiftBlock(uint8_t* block){
	for (int i=0;i<BLOCK_BYTESIZE-1;i++){
		block[i] = block[i]>>1;
		if (block[i+1]&1)
			block[i] = block[i] || 0x80;
		block[i+1] = block[i+1]>>1;		
	}
}

void AESGCM::partialInc(uint8_t* block, int s){
	uint8_t byte;
	for (int i=0; i<s>>3;i++){
		byte = block[i];
		if (i<s>>3){
			if (byte==0xFF){
				block[i]=0x00;
				//--	continue add 1 to next byte
			}
			else{
				block[i]=block[i]+1;
				//--	finish, break loop
				break;
			}
		}
		else{			
			uint8_t mask = 0xFF>>(s-(s>>3)<<3);
			byte = (byte + 1) & mask;
			block[i] = block[i]&(~mask) | byte;			
		}
	}
}

bool AESGCM::mulBlock(uint8_t* blockZ, const uint8_t* blockX, const uint8_t* blockY){	
	
	uint8_t* blockV = (uint8_t*)malloc(BLOCK_BYTESIZE);
	uint8_t bitCheck = 0x01;
	memset(blockZ, 0, BLOCK_BYTESIZE);
	memcpy(blockV, blockY, BLOCK_BYTESIZE);
	for (int i=0;i<BLOCK_BITSIZE;i++){
		//--	check if blockX[bit-i] == 1
		if (blockCopyX[i>>3] & (bitCheck<<(i%8))){
			xorBlock(blockZ, blockZ, blockV);
		}		
		if (blockV[0] & 1){
			bitRightShiftBlock(blockV);
			xorBlock(blockV, blockV, staticVariables.blockR);
		}
		else{
			bitRightShiftBlock(blockV);
		}
	}
}

bool AESGCM::gHash(const uint8_t* block, size_t blockLen, uint8_t* hash){
	if (blockLen<=0 || blockLen%BLOCK_BYTESIZE!=0){
		throw ERROR_DATALENGTH_NOT_SUPPORTED;
	}	
	uint8_t* blockX = (uint8_t*)malloc(BLOCK_BYTESIZE);
	memset(hash, 0, BLOCK_LENGTH);
	int m = blockLen/BLOCK_BYTESIZE;
	for (int i=0; i<m; i++){
		memcpy(blockX, block + i*BLOCK_BYTESIZE, BLOCK_BYTESIZE);
		xorBlock(hash, hash, blockX);
		mulBlock(hash, hash, staticVariables.hashSubKey)
	}	
}



//----------------------------------------//

AESGCM::AESGCM(int keyLength){	
	
	if (keyLength<=0 || keyLength%BLOCK_BITSIZE!=0){
		throw ERROR_KEYLENGTH_NOT_SUPPORTED;
	}
	this->keyLength = keyLength;
	this->key = (uint8_t*)malloc(keyLength>>3);		
}

void AESGCM::setKey(const uint8_t* key, enum SecurityParameter secuParam){
	memcpy(this->key, key, this->keyLength>>3);
	this->secuParam = secuParam;
}

AESGCM::~AEGGCM(){
	//--	securely remove the key by setting its value to 0
	memset(this->key, 0, this->keyLength);
	delete this->key;
}

bool encrypt(const uint8_t* data, const size_t* dataLen, uint8_t* encrypted, size_t* encryptedLen){
}

bool decrypt(const uint8_t* encrypted, const size_t* encryptedLen, uint8_t* data, size_t* dataLen){
}
