#include "AESGCM.h"

#include <cstring>
using namespace std;


//--	private class methods			--//
void AESGCM::xorBlock(uint8_t* blockZ, const uint8_t* blockX, const uint8_t* blockY){
	for (int i=0;i<BLOCK_SIZE; i++){
		blockZ[i] = blockX[i]^blockY[i];
	}
}

void AESGCM::bitRightShiftBlock(uint8_t* block){
	for (int i=0;i<BLOCK_SIZE-1;i++){
		block[i] = block[i]>>1;
		if (block[i+1]&1)
			block[i] = block[i] || 0x80;
		block[i+1] = block[i+1]>>1;		
	}
}

void AESGCM::inc32(uint8_t* block){
	uint32_t last = *((uint32_t*)(block+BLOCK_SIZE-1-4));
	if (last == 0xFFFFFFFF){
		last = 0x00000000;
	}
	else{
		last++;
	}
	memcpy(block+BLOCK_SIZE-1-4, (uint8_t*)&last, 4);
}

void AESGCM::dec32(uint8_t* block){
	uint32_t last = *((uint32_t*)(block+BLOCK_SIZE-1-4));
	if (last == 0x00000000){
		last = 0xFFFFFFFF;
	}
	else{
		last--;
	}
	memcpy(block+BLOCK_SIZE-1-4, (uint8_t*)&last, 4);
}

bool AESGCM::mulBlock(uint8_t* blockZ, const uint8_t* blockX, const uint8_t* blockY){	
	
	uint8_t* blockV = (uint8_t*)malloc(BLOCK_SIZE);
	uint8_t bitCheck = 0x01;
	memset(blockZ, 0, BLOCK_SIZE);
	memcpy(blockV, blockY, BLOCK_SIZE);
	for (int i=0;i<BLOCK_SIZE*8;i++){
		//--	check if blockX[bit-i] == 1
		if (blockX[i>>3] & (bitCheck<<(i%8))){
			xorBlock(blockZ, blockZ, blockV);
		}		
		if (blockV[0] & 1){
			bitRightShiftBlock(blockV);
			xorBlock(blockV, blockV, this->blockR);
		}
		else{
			bitRightShiftBlock(blockV);
		}
	}
}

bool AESGCM::gHash(const uint8_t* block, uint32_t blockLen, uint8_t* hash){
	if (blockLen<=0 || blockLen%BLOCK_SIZE!=0){
		throw ERROR_DATALENGTH_NOT_SUPPORTED;
	}	
	uint8_t* blockX = (uint8_t*)malloc(BLOCK_SIZE);
	memset(hash, 0, BLOCK_SIZE);
	int m = blockLen/BLOCK_SIZE;
	for (int i=0; i<m; i++){
		memcpy(blockX, block + i*BLOCK_SIZE, BLOCK_SIZE);
		xorBlock(hash, hash, blockX);
		mulBlock(hash, hash, this->hashSubKey);
	}
}

void AESGCM::gCTR(const uint8_t* icb, const uint8_t* xstr, uint8_t* ystr, uint32_t strLen){
	
	if (strLen>0){
		uint8_t* cb = (uint8_t*)malloc(BLOCK_SIZE);
		uint8_t* cbC = (uint8_t*)malloc(BLOCK_SIZE);
		int lastBlockSize = strLen%BLOCK_SIZE;
		int n;
		if (lastBlockSize>0){
			n = (strLen + (BLOCK_SIZE - lastBlockSize))/BLOCK_SIZE;
		}
		else{
			n = strLen/BLOCK_SIZE;
			lastBlockSize = BLOCK_SIZE;
		}		
		
		memcpy(cb, icb, BLOCK_SIZE);
		for (int i=1; i<=n-1; i++){
			this->aes256->encryptBlock(cb, cbC);
			xorBlock(ystr+(i-1)*BLOCK_SIZE, cbC, xstr+(i-1)*BLOCK_SIZE);
			inc32(cb);
		}
		this->aes256->encryptBlock(cb, cbC);
		memset(cb, 0, BLOCK_SIZE);
		memcpy(cb, xstr+(n-1)*BLOCK_SIZE, lastBlockSize);
		xorBlock(cb, cb, cbC);
		memcpy(ystr+(n-1)*BLOCK_SIZE, cb, lastBlockSize);
		delete cb;
		delete cbC;
	}
	//--	else: do nothing with empty string
}

//----------------------------------------//

AESGCM::AESGCM(const uint8_t* key, enum SecurityParameter secuParam){	
	this->aes256 = new AES256(key);
	this->secuParam = secuParam;
	//--	init blockR
	this->blockR = (uint8_t*)malloc(BLOCK_SIZE);
	memset(this->blockR, 0, BLOCK_SIZE);
	this->blockR[BLOCK_SIZE-1] = 0xE1;
	//--	generate gHash subkey
	this->hashSubKey = (uint8_t*)malloc(BLOCK_SIZE);
	memset(hashSubKey, 0, BLOCK_SIZE);
	aes256->encryptBlock(hashSubKey, hashSubKey);	
}

AESGCM::~AESGCM(){
	//--	securely remove the key by setting its value to 0
	delete this->aes256;
	delete this->hashSubKey;
	delete this->blockR;
}

bool AESGCM::encrypt(const uint8_t* iv, uint32_t ivLen, const uint8_t* data, uint32_t dataLen, const uint8_t* aad, uint32_t aadLen, uint8_t** encrypted, uint32_t* encryptedLen, uint8_t** tag, uint32_t* tagLen){
	//--	1. H has been calculated before
	//--	2. define blockJ
	uint8_t* blockJ;
	uint32_t blockJLen;
	
	if (ivLen == 12){ //--	96 bits = 12 bytes
		blockJLen = BLOCK_SIZE;
		blockJ = (uint8_t*)malloc(blockJLen);
		memset(blockJ, 0, BLOCK_SIZE);
		memcpy(blockJ, iv, 12);
		blockJ[BLOCK_SIZE-1] = 0x01;		
	}
	else{
		int s = ivLen%BLOCK_SIZE==0? 0 : BLOCK_SIZE - ivLen%BLOCK_SIZE;
		blockJLen = ivLen + s + BLOCK_SIZE;
		blockJ = (uint8_t*)malloc(blockJLen);
		memset(blockJ, 0, blockJLen);
		memcpy(blockJ, iv, ivLen);
		memcpy(blockJ+blockJLen-1-4, (uint8_t*)&ivLen, 4); //--	copy 4 bytes ivLen to blockJ last 4 bytes
		gHash(blockJ, blockJLen, blockJ);
	}
	//--	3. calculate C(ipher)
	*encrypted = (uint8_t*)malloc(dataLen);
	*encryptedLen = dataLen;
	inc32(blockJ);
	gCTR(blockJ, data, *encrypted, dataLen);
	dec32(blockJ);	
	//--	4. calculate u, v
	int u = dataLen%BLOCK_SIZE==0? 0 : BLOCK_SIZE - dataLen%BLOCK_SIZE;
	int v = aadLen%BLOCK_SIZE==0? 0 : BLOCK_SIZE - aadLen%BLOCK_SIZE;
	//--	5. define blockS
	uint32_t blockSLen = aadLen + v + dataLen + u + BLOCK_SIZE;
	uint8_t* blockS = (uint8_t*)malloc(blockSLen);
	memset(blockS, 0, blockSLen);
	memcpy(blockS, aad, aadLen);
	memcpy(blockS + (aadLen+v)/BLOCK_SIZE, *encrypted, *encryptedLen);
	memcpy(blockS + (aadLen+v+*encryptedLen+u)/BLOCK_SIZE + 4, (uint8_t*)&aadLen, 4);
	memcpy(blockS + (aadLen+v+*encryptedLen+u)/BLOCK_SIZE + 8 + 4 , (uint8_t*)encryptedLen, 4);
	gHash(blockS, blockSLen, blockS);
	//--	6. calculate T
	*tagLen = this->secuParam/8;
	*tag = (uint8_t*)malloc(*tagLen);
	gCTR(blockJ, blockS, blockS, blockSLen);
	memcpy(*tag, blockS, *tagLen);
	//--	7. return
	return true;
}

bool AESGCM::decrypt(const uint8_t* encrypted, const size_t* encryptedLen, uint8_t* data, size_t* dataLen){
}


int main(int argc, char** argv){
	string keyHexString = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
	uint8_t key[KEY_LENGTH];
	stringToHex(keyHexString, key);
	
	AESGCM* aesGCM = new AESGCM(key, SECU_128);
	
	
	aesGCM->encrypt();
	
}
