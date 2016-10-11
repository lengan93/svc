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
	
	uint8_t* blockV = (uint8_t*)malloc(BLOCK_SIZE);
	uint8_t* blockXCopy = (uint8_t*)malloc(BLOCK_SIZE);
		
	int i, j;

	memcpy(blockXCopy, blockX, BLOCK_SIZE);
	memcpy(blockV, blockY, BLOCK_SIZE); //--	V_0 = Y
	memset(blockZ, 0, BLOCK_SIZE); //--	Z_0 = 0^128
	
	for (i = 0; i < 16; i++) {
		for (j = 0; j < 8; j++) {
			if (blockXCopy[i] & BIT(7 - j)) {
				//--	Z_(i + 1) = Z_i XOR V_i
				xorBlock(blockZ, blockZ, blockV);
			} else {
				//--	Z_(i + 1) = Z_i
				xorBlock(blockZ, blockZ, this->blockZero); //--	side channel counter mesure: timing attack
			}

			if (blockV[BLOCK_SIZE-1] & 0x01) {				
				bitRightShiftBlock(blockV); //--	V_(i + 1) = (V_i >> 1) XOR R
				blockV[0] ^= 0xe1; //--		R = 11100001 || 0^120
			} else {
				//--	V_(i + 1) = V_i >> 1
				bitRightShiftBlock(blockV);
				blockV[0] ^= 0x00; //--	side channel counter mesure: timing attack
			}
		}
	}
	
	delete blockV;
	delete blockXCopy;
}


void AESGCM::gHash(uint8_t* hash, const uint8_t* data, uint32_t dataLen){

	memset(hash, 0, BLOCK_SIZE);
	int m = dataLen/BLOCK_SIZE;
	for (int i=0; i<m; i++){		
		xorBlock(hash, hash, data+i*BLOCK_SIZE);
		mulBlock(hash, hash, this->hashSubKey);		
	}
}

void AESGCM::gCTR(const uint8_t* icb, const uint8_t* xstr, uint8_t* ystr, uint32_t strLen){
		
	if (strLen>0){
		uint8_t* cb = (uint8_t*)malloc(BLOCK_SIZE); //-- counter
		uint8_t* cbC = (uint8_t*)malloc(BLOCK_SIZE); //-- encrypted counter
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
		
		delete cb;
		delete cbC;
	}
	//--	else: do nothing with empty string
}

void AESGCM::prepareBlockJ(const uint8_t* iv, uint32_t ivLen){
	
	if (ivLen == 12){ //--	96 bits = 12 bytes		
		memset(blockJ, 0, BLOCK_SIZE);
		memcpy(blockJ, iv, 12);
		blockJ[BLOCK_SIZE-1] = 0x01;
	}
	else{
		int s = ivLen%BLOCK_SIZE==0? 0 : BLOCK_SIZE - ivLen%BLOCK_SIZE;
		uint32_t blockCounterLen = ivLen + s + BLOCK_SIZE;
		uint8_t* blockCounter = (uint8_t*)malloc(blockCounterLen);
		memset(blockCounter, 0, blockCounterLen);
		memcpy(blockCounter, iv, ivLen);
		//--	copy 4 bytes ivLen last 4 bytes
		PUT_BE32(blockCounter + blockCounterLen - 4, ivLen<<3);
		//-- gHash		
		gHash(blockJ, blockCounter, blockCounterLen);		
		delete blockCounter;
	}
}

//----------------------------------------//

AESGCM::AESGCM(const uint8_t* key, enum SecurityParameter secuParam){	
	this->aes256 = new AES256(key);
	this->secuParam = secuParam;
	this->blockJ = (uint8_t*)malloc(BLOCK_SIZE);
	
	//-- blockZero used in counter mesure
	this->blockZero = (uint8_t*)malloc(BLOCK_SIZE);
	memset(this->blockZero, 0, BLOCK_SIZE);	
	
	//-- generate gHash subkey
	this->hashSubKey = (uint8_t*)malloc(BLOCK_SIZE);
	memset(hashSubKey, 0, BLOCK_SIZE);
	aes256->encryptBlock(hashSubKey, hashSubKey);
}

AESGCM::~AESGCM(){
	delete this->aes256;
	memset(this->hashSubKey, 0, BLOCK_SIZE); //--	securely remove the key by setting its value to 0
	delete this->hashSubKey;
	delete this->blockZero;
}

void AESGCM::encrypt(const uint8_t* iv, uint32_t ivLen, const uint8_t* data, uint32_t dataLen, const uint8_t* aad, uint32_t aadLen, uint8_t** encrypted, uint32_t* encryptedLen, uint8_t** tag, uint32_t* tagLen){
	//--	1. H has been calculated before
	//--	2. prepare blockJ	
	prepareBlockJ(iv, ivLen);
	
	//--	3. calculate C(ipher)
	*encrypted = (uint8_t*)malloc(dataLen);
	*encryptedLen = dataLen;
	inc32(this->blockJ);
	gCTR(this->blockJ, data, *encrypted, dataLen);
	dec32(this->blockJ);
	
	//--	4. calculate u, v
	int u = dataLen%BLOCK_SIZE==0? 0 : BLOCK_SIZE - dataLen%BLOCK_SIZE;
	int v = aadLen%BLOCK_SIZE==0? 0 : BLOCK_SIZE - aadLen%BLOCK_SIZE;
	//-- define blockS
	uint32_t blockSLen = aadLen + v + dataLen + u + BLOCK_SIZE;
	uint8_t* blockS = (uint8_t*)malloc(blockSLen);
	memset(blockS, 0, blockSLen);
	memcpy(blockS, aad, aadLen);
	memcpy(blockS + (aadLen+v), *encrypted, *encryptedLen);
	//-- add aadLen and encryptedLen, bit (not byte) length
	//aadLen<<=3;
	//*encryptedLen<<=3;
	//uint8_t* p = (uint8_t*)&aadLen;
	//uint8_t* q = (uint8_t*)encryptedLen;
	PUT_BE32(blockS + blockSLen-4, *encryptedLen<<3);
	PUT_BE32(blockS + blockSLen-12, aadLen<<3);
	/*
	for (int i=1;i<=4; i++){
		//-- copy encryptedLen
		blockS[blockSLen - i] = q[i-1];
		//-- copy aadLen, skip 8 bytes = 64 bits of encryptedLen
		blockS[blockSLen - 8 - i] = p[i-1];
	}
	aadLen>>=3;
	*encryptedLen>>=3;
	*/
	uint8_t* hashBlockS = (uint8_t*)malloc(BLOCK_SIZE);;
	gHash(hashBlockS, blockS, blockSLen);	
	
	//--	5. calculate T
	*tagLen = this->secuParam/8;
	*tag = (uint8_t*)malloc(*tagLen);
	gCTR(this->blockJ, hashBlockS, blockS, blockSLen);
	memcpy(*tag, blockS, *tagLen);
	
	//--	6. clear and return
	delete hashBlockS;
	delete blockS;	
}

bool AESGCM::decrypt(const uint8_t* iv, uint32_t ivLen, const uint8_t* encrypted, uint32_t encryptedLen, const uint8_t* aad, uint32_t aadLen, const uint8_t* tag, uint32_t tagLen, uint8_t** data, uint32_t* dataLen){
	if (tagLen != this->secuParam/8){
		return false;
	}
	
}

int main(int argc, char** argv){
	string keyHexString = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
	uint8_t key[KEY_LENGTH];
	stringToHex(keyHexString, key);	
	AESGCM* aesGCM = new AESGCM(key, SECU_128);
	
	string ivHex = "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b";
	uint32_t ivLen = ivHex.size()/2;
	uint8_t iv[ivLen];
	stringToHex(ivHex, iv);
	//generateRandomData(ivLen, iv);
	
	string dataHex = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
	uint32_t dataLen = dataHex.size()/2;
	uint8_t dataBin[dataLen];
	stringToHex(dataHex, dataBin);
	
	string aadHex = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
	uint32_t aadLen = aadHex.size()/2;
	uint8_t aadBin[aadLen];
	stringToHex(aadHex, aadBin);
	
	uint8_t* encrypted;
	uint32_t encryptedLen;
	uint8_t* tag;
	uint32_t tagLen;
	
	printf("\nraw data: \n");
	printBuffer(dataBin, dataLen);
	
	printf("\nIv: \n");
	printBuffer(iv, ivLen);
	
	aesGCM->encrypt(iv, ivLen, dataBin, dataLen, aadBin, aadLen, &encrypted, &encryptedLen, &tag, &tagLen);
	
	printf("\nEncrypted data: \n");
	printBuffer(encrypted, encryptedLen);
	printf("\nAuthentication tag: \n");
	printBuffer(tag, tagLen);

}

