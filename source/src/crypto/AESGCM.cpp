#include "AESGCM.h"

using namespace std;

//--	private class methods			--//
void AESGCM::xorBlock(uint8_t* blockZ, const uint8_t* blockX, const uint8_t* blockY){
	for (int i=0;i<BLOCK_SIZE; i++){
		blockZ[i] = blockX[i]^blockY[i];
	}
}

void AESGCM::dec32(uint8_t *block){
	uint32_t val;
	val = GET_BE32(block + BLOCK_SIZE - 4);
	val--;
	PUT_BE32(block + BLOCK_SIZE - 4, val);
}

void AESGCM::inc32(uint8_t *block){
	uint32_t val;
	val = GET_BE32(block + BLOCK_SIZE - 4);
	val++;
	PUT_BE32(block + BLOCK_SIZE - 4, val);
}

void AESGCM::bitRightShiftBlock(uint8_t* block)
{
	uint32_t val;

	val = GET_BE32(block + 12);
	val >>= 1;
	if (block[11] & 0x01)
		val |= 0x80000000;
	PUT_BE32(block + 12, val);

	val = GET_BE32(block + 8);
	val >>= 1;
	if (block[7] & 0x01)
		val |= 0x80000000;
	PUT_BE32(block + 8, val);

	val = GET_BE32(block + 4);
	val >>= 1;
	if (block[3] & 0x01)
		val |= 0x80000000;
	PUT_BE32(block + 4, val);

	val = GET_BE32(block + 0);
	val >>= 1;
	PUT_BE32(block, val);
}

void AESGCM::mulBlock(uint8_t* blockZ, const uint8_t* blockX, const uint8_t* blockY){	
	
	uint8_t blockV[BLOCK_SIZE];
	uint8_t blockXCopy[BLOCK_SIZE];
		
	int i, j;

	memcpy(blockXCopy, blockX, BLOCK_SIZE);
	memcpy(blockV, blockY, BLOCK_SIZE); //--	V_0 = Y
	memset(blockZ, 0, BLOCK_SIZE); //--	Z_0 = 0^128
	
	for (i = 0; i < 16; i++) {
		for (j = 0; j < 8; j++) {
			if (blockXCopy[i] & BIT(7 - j)) {
				//--	Z_(i + 1) = Z_i XOR V_i
				xorBlock(blockZ, blockZ, blockV);
			}
			else {
				//--	Z_(i + 1) = Z_i
				xorBlock(blockZ, blockZ, this->blockZero); //--	side channel counter mesure: timing attack
			}

			if (blockV[BLOCK_SIZE-1] & 0x01) {				
				bitRightShiftBlock(blockV); //--	V_(i + 1) = (V_i >> 1) XOR R
				blockV[0] ^= 0xe1; //--		R = 11100001 || 0^120
			}
			else {
				//--	V_(i + 1) = V_i >> 1
				bitRightShiftBlock(blockV);
				blockV[0] ^= 0x00; //--	side channel counter mesure: timing attack
			}
		}
	}
}


void AESGCM::gHash(uint8_t* hash, const uint8_t* data, uint32_t dataLen){

	memset(hash, 0, BLOCK_SIZE);
	int m = dataLen/BLOCK_SIZE;
	for (int i=0; i<m; i++){		
		xorBlock(hash, hash, data+i*BLOCK_SIZE);
		mulBlock(hash, hash, this->hashSubKey);		
	}
}

void AESGCM::gCTR(uint8_t* ystr, const uint8_t* icb, const uint8_t* xstr, uint32_t strLen){
	
	if (strLen>0){		
		uint8_t cb[BLOCK_SIZE]; //-- counter
		uint8_t cbC[BLOCK_SIZE]; //-- encrypted counter
		int lastBlockSize = strLen%BLOCK_SIZE;
		
		int n;	
		//-- calculate last block's length
		if (lastBlockSize>0){
			n = (strLen + (BLOCK_SIZE - lastBlockSize))/BLOCK_SIZE;
		}
		else{
			n = strLen/BLOCK_SIZE;
			lastBlockSize = BLOCK_SIZE;
		}
		
		//-- encrypt first n-1 blocks
		memcpy(cb, icb, BLOCK_SIZE);
		for (int i=1; i<=n-1; i++){
			this->aes256->encryptBlock(cb, cbC);	
			xorBlock(ystr+(i-1)*BLOCK_SIZE, cbC, xstr+(i-1)*BLOCK_SIZE);
			inc32(cb);					
		}
		
		//-- encrypt last block
		this->aes256->encryptBlock(cb, cbC);
		memcpy(cb, xstr+(n-1)*BLOCK_SIZE, lastBlockSize);
		xorBlock(cb, cb, cbC);
		memcpy(ystr+(n-1)*BLOCK_SIZE, cb, lastBlockSize);				
	}
}

void AESGCM::prepBlockJ(const uint8_t* iv, uint32_t ivLen){
	
	if (ivLen == 12){ //--	96 bits = 12 bytes		
		memset(blockJ, 0, BLOCK_SIZE);
		memcpy(blockJ, iv, 12);
		blockJ[BLOCK_SIZE-1] = 0x01;
	}
	else{
		int s = ivLen%BLOCK_SIZE==0? 0 : BLOCK_SIZE - ivLen%BLOCK_SIZE;
		uint32_t blockCounterLen = ivLen + s + BLOCK_SIZE;
		uint8_t blockCounter[blockCounterLen];
		memset(blockCounter, 0, blockCounterLen);
		memcpy(blockCounter, iv, ivLen);
		//--	copy 4 bytes ivLen last 4 bytes
		PUT_BE32(blockCounter + blockCounterLen - 4, ivLen<<3);
		//-- gHash		
		gHash(blockJ, blockCounter, blockCounterLen);
	}
}

void AESGCM::calcBlockS(const uint8_t* aad, uint32_t aadLen, const uint8_t* encrypted, uint32_t encryptedLen){
	//-- calculate u, v
	int u = encryptedLen%BLOCK_SIZE==0? 0 : BLOCK_SIZE - encryptedLen%BLOCK_SIZE;
	int v = aadLen%BLOCK_SIZE==0? 0 : BLOCK_SIZE - aadLen%BLOCK_SIZE;
	//-- define blockHold
	uint32_t blockHoldLen = aadLen + v + encryptedLen + u + BLOCK_SIZE;
	uint8_t blockHold[blockHoldLen];
	memset(blockHold, 0, blockHoldLen);
	memcpy(blockHold, aad, aadLen);
	memcpy(blockHold + aadLen+v, encrypted, encryptedLen);
	//-- add aadLen and encryptedLen, bit (not byte) length
	PUT_BE32(blockHold + blockHoldLen-4, encryptedLen<<3);
	PUT_BE32(blockHold + blockHoldLen-12, aadLen<<3);
	
	gHash(this->blockS, blockHold, blockHoldLen);
}

//----------------------------------------//

AESGCM::AESGCM(const uint8_t* key, enum SecurityParameter secuParam){	
	this->aes256 = new AES256(key);
	this->secuParam = secuParam;
	
	//-- blockZero used in counter mesure
	memset(this->blockZero, 0, BLOCK_SIZE);
	
	//-- generate gHash subkey
	memset(hashSubKey, 0, BLOCK_SIZE);
	aes256->encryptBlock(hashSubKey, hashSubKey);
}

AESGCM::~AESGCM(){
	delete this->aes256;
	memset(this->hashSubKey, 0, BLOCK_SIZE); //--	securely remove the key by setting its value to 0
}

void AESGCM::encrypt(const uint8_t* iv, uint32_t ivLen, const uint8_t* data, uint32_t dataLen, const uint8_t* aad, uint32_t aadLen, uint8_t** encrypted, uint32_t* encryptedLen, uint8_t** tag, uint32_t* tagLen){
	//--	1. H has been calculated before
	//--	2. prepare blockJ	
	prepBlockJ(iv, ivLen);
	
	//--	3. chiffer
	inc32(this->blockJ);
	*encryptedLen = dataLen;
	*encrypted = (uint8_t*)malloc(dataLen);
	gCTR(*encrypted, this->blockJ, data, dataLen);
	dec32(this->blockJ);
	
	//--	4. calculate blockS
	calcBlockS(aad, aadLen, *encrypted, dataLen);
	
	//--	5. calculate T
	*tagLen=this->secuParam>>3;
	*tag = (uint8_t*)malloc(*tagLen);
	gCTR(blockS, this->blockJ, this->blockS, BLOCK_SIZE);//-- reuse blockS to contain result
	memcpy(*tag, blockS, *tagLen);
}

bool AESGCM::decrypt(const uint8_t* iv, uint32_t ivLen, const uint8_t* encrypted, uint32_t encryptedLen, const uint8_t* aad, uint32_t aadLen, const uint8_t* tag, uint32_t tagLen, uint8_t** data, uint32_t* dataLen){
	//--	1. check lengths
	if (tagLen!=this->secuParam>>3) return false;
	//--	2. generate blockJ
	prepBlockJ(iv, ivLen);
	
	//--	3. dechiffer
	inc32(this->blockJ);
	*dataLen = encryptedLen;
	*data = (uint8_t*)malloc(encryptedLen);
	gCTR(*data, this->blockJ, encrypted, encryptedLen);
	dec32(this->blockJ);
	
	//--	4. calculate blockS
	calcBlockS(aad, aadLen, encrypted, encryptedLen);
	
	//--	5. calculate T'
	uint8_t* tagT = (uint8_t*)malloc(tagLen);
	gCTR(this->blockS, this->blockJ, this->blockS, BLOCK_SIZE);//-- reuse blockS to contain result
	memcpy(tagT, blockS, tagLen);
	
	//--	6. return
	return memcmp(tagT, tag, tagLen)==0;	
}
