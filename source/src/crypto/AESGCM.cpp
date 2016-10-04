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
	uint32_t last;
	uint8_t* p = (uint8_t*)&last;
	//--	copy from block
	for (int i=1;i<=4;i++){
		p[i-1] = block[BLOCK_SIZE-i];
	}
	//--	increase by 1
	if (last == 0xFFFFFFFF){
		last = 0x00000000;
	}
	else{
		last++;
	}
	//--	copy back to block
	for (int i=1;i<=4;i++){
		block[BLOCK_SIZE-i] = p[i-1];
	}	
}

void AESGCM::dec32(uint8_t* block){
	uint32_t last;
	uint8_t* p = (uint8_t*)&last;
	//--	copy from block
	for (int i=1;i<=4;i++){
		p[i-1] = block[BLOCK_SIZE-i];
	}
	//--	decrease by 1
	if (last == 0x00000000){
		last = 0xFFFFFFFF;
	}
	else{
		last--;
	}
	//--	copy back to block
	for (int i=1;i<=4;i++){
		block[BLOCK_SIZE-i] = p[i-1];
	}	
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
	delete blockV;
}

bool AESGCM::gHash(const uint8_t* data, uint32_t dataLen, uint8_t** hash){
	if (dataLen<=0 || dataLen%BLOCK_SIZE!=0){
		throw ERROR_DATALENGTH_NOT_SUPPORTED;
	}
	//uint8_t* blockX = (uint8_t*)malloc(BLOCK_SIZE);
	*hash = (uint8_t*)malloc(BLOCK_SIZE);
	memset(*hash, 0, BLOCK_SIZE);
	int m = dataLen/BLOCK_SIZE;
	for (int i=0; i<m; i++){		
		//memcpy(blockX, data + i*BLOCK_SIZE, BLOCK_SIZE);
		xorBlock(*hash, *hash, data+i*BLOCK_SIZE);
		printf("\nxorBlock: ");
		printBuffer(*hash, BLOCK_SIZE);
		mulBlock(*hash, *hash, this->hashSubKey);
		printf("\nmulBlock: ");
		printBuffer(*hash, BLOCK_SIZE);
	}
	//delete blockX;
}

void AESGCM::gCTR(const uint8_t* icb, const uint8_t* xstr, uint8_t* ystr, uint32_t strLen){
	
	printf("\ngCTR-----------------\n");
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
		
		printf("\nlast block size: %d\n", lastBlockSize);	
		
		memcpy(cb, icb, BLOCK_SIZE);
		for (int i=1; i<=n-1; i++){
			printf("\nCounter:\n");
			printBuffer(cb, BLOCK_SIZE);
			this->aes256->encryptBlock(cb, cbC);
			printf("\EncryptedCounter:\n");
			printBuffer(cbC, BLOCK_SIZE);
			
			xorBlock(ystr+(i-1)*BLOCK_SIZE, cbC, xstr+(i-1)*BLOCK_SIZE);
			inc32(cb);
			
			printf("\nE%d: \n", i);
			printBuffer(ystr+(i-1)*BLOCK_SIZE, BLOCK_SIZE);
		}
		
		printf("\nCounter:\n");
		printBuffer(cb, BLOCK_SIZE);
		this->aes256->encryptBlock(cb, cbC);
		printf("\EncryptedCounter:\n");
		printBuffer(cbC, BLOCK_SIZE);
		memset(cb, 0, BLOCK_SIZE);
		memcpy(cb, xstr+(n-1)*BLOCK_SIZE, lastBlockSize);
		xorBlock(cb, cb, cbC);
		memcpy(ystr+(n-1)*BLOCK_SIZE, cb, lastBlockSize);
		printf("\nLastblock: \n");
		printBuffer(ystr+(n-1)*BLOCK_SIZE, lastBlockSize);
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
	
	printf("\nHashsubKey: \n");
	printBuffer(this->hashSubKey, BLOCK_SIZE);
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
		//--	copy 4 bytes ivLen to blockJ last 4 bytes
		uint8_t* p = (uint8_t*)&ivLen;
		for (int i=1;i<=4;i++){
			blockJ[blockJLen-i] = p[i-1];
		}
		//-- gHash blockJ
		uint8_t* hashBlockJ;
		gHash(blockJ, blockJLen, &hashBlockJ);
		memcpy(blockJ, hashBlockJ, BLOCK_SIZE);
		delete hashBlockJ;
	}
	printf("\nblockJ: \n");
	printBuffer(blockJ, blockJLen);
	
	//--	3. calculate C(ipher)
	*encrypted = (uint8_t*)malloc(dataLen);
	*encryptedLen = dataLen;
	inc32(blockJ);
	gCTR(blockJ, data, *encrypted, dataLen);
	dec32(blockJ);
	//--	4. calculate u, v
	int u = dataLen%BLOCK_SIZE==0? 0 : BLOCK_SIZE - dataLen%BLOCK_SIZE;
	int v = aadLen%BLOCK_SIZE==0? 0 : BLOCK_SIZE - aadLen%BLOCK_SIZE;
	printf("\nu=%d, v=%d\n", u, v);
	
	//--	5. define blockS
	uint32_t blockSLen = aadLen + v + dataLen + u + BLOCK_SIZE;
	uint8_t* blockS = (uint8_t*)malloc(blockSLen);
	printf("\nblockSLen: %d\n", blockSLen);
	memset(blockS, 0, blockSLen);
	memcpy(blockS, aad, aadLen);
	memcpy(blockS + (aadLen+v), *encrypted, *encryptedLen);
	//-- add aadLen and encryptedLen
	uint8_t* p = (uint8_t*)&aadLen;
	uint8_t* q = (uint8_t*)encryptedLen;	
	for (int i=1;i<=4; i++){
		//-- copy encryptedLen
		blockS[blockSLen - i] = q[i-1];
		//-- copy aadLen, skip 8 bytes = 64 bits of encryptedLen
		blockS[blockSLen - 8 - i] = p[i-1];
	}
	
	printf("\nblockS before gHash: \n");
	printBuffer(blockS, blockSLen);	
	uint8_t* hashBlockS;
	gHash(blockS, blockSLen, &hashBlockS);
	
	printf("\nblockS hashed: \n");
	printBuffer(hashBlockS, BLOCK_SIZE);
	
	//--	6. calculate T
	*tagLen = this->secuParam/8;
	*tag = (uint8_t*)malloc(*tagLen);
	gCTR(blockJ, blockS, blockS, blockSLen);
	memcpy(*tag, blockS, *tagLen);
	//--	7. clear and return
	delete blockS;
	delete blockJ;
	return true;
}

bool AESGCM::decrypt(const uint8_t* encrypted, const size_t* encryptedLen, uint8_t* data, size_t* dataLen){
	
}


int main(int argc, char** argv){
	string keyHexString = "E3C08A8F06C6E3AD95A70557B23F75483CE33021A9C72B7025666204C69C0B72";
	uint8_t key[KEY_LENGTH];
	stringToHex(keyHexString, key);	
	AESGCM* aesGCM = new AESGCM(key, SECU_128);
	
	string ivHex = "12153524C0895E81B2C28465";
	uint32_t ivLen = ivHex.size()/2;
	uint8_t iv[ivLen];
	stringToHex(ivHex, iv);
	//generateRandomData(ivLen, iv);
	
	string dataHex = "08000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A0002";
	uint32_t dataLen = dataHex.size()/2;
	uint8_t dataBin[dataLen];
	stringToHex(dataHex, dataBin);
	
	string aadHex = "D609B1F056637A0D46DF998D88E52E00B2C2846512153524C0895E81";
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
