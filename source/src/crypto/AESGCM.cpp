#include "AESGCM.h"

#include <cstring>
#include <iostream>

using namespace std;


//--	private class methods			--//
void AESGCM::xorBlock(uint8_t* blockZ, const uint8_t* blockX, const uint8_t* blockY){
	for (int i=0;i<BLOCK_SIZE; i++){
		blockZ[i] = blockX[i]^blockY[i];
	}
}

/*
void AESGCM::bitRightShiftBlock(uint8_t* block){
	for (int i=0;i<BLOCK_SIZE-1;i++){		
		block[i] = (block[i]<<1) | ((block[i+1] & 0x80)>>7);		
	}
	block[BLOCK_SIZE-1]<<=1;
}*/

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

void AESGCM::bitRightShiftBlock(uint8_t *v)
{
	uint32_t val;

	val = GET_BE32(v + 12);
	val >>= 1;
	if (v[11] & 0x01)
		val |= 0x80000000;
	PUT_BE32(v + 12, val);

	val = GET_BE32(v + 8);
	val >>= 1;
	if (v[7] & 0x01)
		val |= 0x80000000;
	PUT_BE32(v + 8, val);

	val = GET_BE32(v + 4);
	val >>= 1;
	if (v[3] & 0x01)
		val |= 0x80000000;
	PUT_BE32(v + 4, val);

	val = GET_BE32(v);
	val >>= 1;
	PUT_BE32(v, val);
}

bool AESGCM::mulBlock(uint8_t* blockZ, const uint8_t* blockX, const uint8_t* blockY){	
	
	uint8_t* blockCopyX = (uint8_t*)malloc(BLOCK_SIZE);
	uint8_t* blockCopyY = (uint8_t*)malloc(BLOCK_SIZE);
	uint8_t* blockV = (uint8_t*)malloc(BLOCK_SIZE);
	//uint8_t* blockZ = (uint8_t*)malloc(BLOCK_SIZE);
	memcpy(blockCopyX, blockX, BLOCK_SIZE);
	memcpy(blockCopyY, blockY, BLOCK_SIZE);
		
	int i, j;

	memset(blockZ, 0, BLOCK_SIZE); /* Z_0 = 0^128 */
	memcpy(blockV, blockY, BLOCK_SIZE); /* V_0 = Y */

	for (i = 0; i < 16; i++) {
		for (j = 0; j < 8; j++) {
			if (blockCopyX[i] & BIT(7 - j)) {
				/* Z_(i + 1) = Z_i XOR V_i */
				xorBlock(blockZ, blockZ, blockV);
			} else {
				/* Z_(i + 1) = Z_i */
			}

			if (blockV[BLOCK_SIZE-1] & 0x01) {
				/* V_(i + 1) = (V_i >> 1) XOR R */
				bitRightShiftBlock(blockV);
				/* R = 11100001 || 0^120 */
				blockV[0] ^= 0xe1;
			} else {
				/* V_(i + 1) = V_i >> 1 */
				bitRightShiftBlock(blockV);
			}
		}
	}	
	/*uint8_t* blockV = (uint8_t*)malloc(BLOCK_SIZE);
	uint8_t* blockCopyY = (uint8_t*)malloc(BLOCK_SIZE);
	uint8_t bitCheck[8] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};
	memcpy(blockCopyY, blockY, BLOCK_SIZE);
	
	//-- V0
	memcpy(blockV, blockX, BLOCK_SIZE);
	//-- Z0
	memset(blockZ, 0, BLOCK_SIZE);

	printf("\n--Y : ");
	printBitString(blockCopyY, BLOCK_SIZE);
	printf("\n--Z0: ");
	printBuffer(blockZ, BLOCK_SIZE);
	printf("\n--V0: ");
	printBitString(blockV, BLOCK_SIZE);

	for (int i=0;i<BLOCK_SIZE*8;i++){
		printf("\n-------i=%d: ", i);
		if ((blockCopyY[BLOCK_SIZE-1-i/8] & bitCheck[i%8]) > 0){
			printf("\nxor Z and V");
			xorBlock(blockZ, blockZ, blockV);
		}
		printf("\nZ=: ");
		printBitString(blockZ, BLOCK_SIZE);	
		
		if ((blockV[0] & 0x80) > 0){
			printf("\nshift blockV and xor R");
			bitRightShiftBlock(blockV);
			xorBlock(blockV, blockV, this->blockR);
		}
		else{
			printf("\nshift blockV");
			bitRightShiftBlock(blockV);
		}
		printf("\nV=: ");
		printBitString(blockV, BLOCK_SIZE);		
	}
	delete blockV;
	delete blockCopyY;
	* */
}


bool AESGCM::gHash(const uint8_t* data, uint32_t dataLen, uint8_t** hash){
	if (dataLen<=0 || dataLen%BLOCK_SIZE!=0){
		throw ERROR_DATALENGTH_NOT_SUPPORTED;
	}
	
	*hash = (uint8_t*)malloc(BLOCK_SIZE);
	memset(*hash, 0, BLOCK_SIZE);

	int m = dataLen/BLOCK_SIZE;
	for (int i=0; i<m; i++){
		//printf("\nX%d: ", i+1);
		xorBlock(*hash, *hash, data+i*BLOCK_SIZE);
		mulBlock(*hash, *hash, this->hashSubKey);
		//printBuffer(*hash, BLOCK_SIZE);		
	}
}

void AESGCM::gCTR(const uint8_t* icb, const uint8_t* xstr, uint8_t* ystr, uint32_t strLen){
	
	//printf("\ngCTR-----------------\n");
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
		
		//printf("\nlast block size: %d\n", lastBlockSize);	
		
		memcpy(cb, icb, BLOCK_SIZE);
		for (int i=1; i<=n-1; i++){
			//printf("\nY%d: ", i);
			//printBuffer(cb, BLOCK_SIZE);
			this->aes256->encryptBlock(cb, cbC);
			//printf("\nE(K,Y%d): ", i);
			//printBuffer(cbC, BLOCK_SIZE);			
			xorBlock(ystr+(i-1)*BLOCK_SIZE, cbC, xstr+(i-1)*BLOCK_SIZE);
			inc32(cb);					
		}
		
		//printf("\nY%d: ", n);
		//printBuffer(cb, BLOCK_SIZE);
		this->aes256->encryptBlock(cb, cbC);
		//printf("\nE(K,Y%d): ", n);
		//printBuffer(cbC, BLOCK_SIZE);
		
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
	memset(this->hashSubKey, 0, BLOCK_SIZE);
	delete this->hashSubKey;
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
		//printf("\nblockJLen: %d", blockJLen);
		PUT_BE32(blockJ + blockJLen - 4, ivLen<<3);
		/*uint8_t* p = (uint8_t*)&ivLen;
		for (int i=1;i<=4;i++){
			blockJ[blockJLen-i] = p[i-1];
		}*/
		//-- gHash blockJ
		uint8_t* hashBlockJ;
		printf("\nblockJ: \n");
		printBuffer(blockJ, blockJLen);
		gHash(blockJ, blockJLen, &hashBlockJ);
		memcpy(blockJ, hashBlockJ, BLOCK_SIZE);
		delete hashBlockJ;
	}
	printf("\nY0: \n");
	printBuffer(blockJ, BLOCK_SIZE);
	
	//--	3. calculate C(ipher)
	*encrypted = (uint8_t*)malloc(dataLen);
	*encryptedLen = dataLen;
	inc32(blockJ);
	gCTR(blockJ, data, *encrypted, dataLen);
	dec32(blockJ);
	
	//--	4. calculate u, v
	int u = dataLen%BLOCK_SIZE==0? 0 : BLOCK_SIZE - dataLen%BLOCK_SIZE;
	int v = aadLen%BLOCK_SIZE==0? 0 : BLOCK_SIZE - aadLen%BLOCK_SIZE;
	//printf("\nu=%d, v=%d\n", u, v);
	
	//--	5. define blockS
	uint32_t blockSLen = aadLen + v + dataLen + u + BLOCK_SIZE;
	uint8_t* blockS = (uint8_t*)malloc(blockSLen);
	//printf("\nblockSLen: %d\n", blockSLen);
	memset(blockS, 0, blockSLen);
	memcpy(blockS, aad, aadLen);
	memcpy(blockS + (aadLen+v), *encrypted, *encryptedLen);
	//-- add aadLen and encryptedLen, bit (not byte) length
	aadLen<<=3;
	*encryptedLen<<=3;
	uint8_t* p = (uint8_t*)&aadLen;
	uint8_t* q = (uint8_t*)encryptedLen;
	for (int i=1;i<=4; i++){
		//-- copy encryptedLen
		blockS[blockSLen - i] = q[i-1];
		//-- copy aadLen, skip 8 bytes = 64 bits of encryptedLen
		blockS[blockSLen - 8 - i] = p[i-1];
	}
	aadLen>>=3;
	*encryptedLen>>=3;
	
	//printf("\nblockS before gHash: \n");
	//printBuffer(blockS, blockSLen);	
	uint8_t* hashBlockS;
	gHash(blockS, blockSLen, &hashBlockS);	
	
	//printf("\nblockS hashed: \n");
	//printBuffer(hashBlockS, BLOCK_SIZE);
	
	//--	6. calculate T
	*tagLen = this->secuParam/8;
	*tag = (uint8_t*)malloc(*tagLen);
	gCTR(blockJ, hashBlockS, blockS, blockSLen);
	memcpy(*tag, blockS, *tagLen);
	//--	7. clear and return
	delete hashBlockS;
	delete blockS;
	delete blockJ;
	return true;
}

bool AESGCM::decrypt(const uint8_t* encrypted, const size_t* encryptedLen, uint8_t* data, size_t* dataLen){
	
}
/*

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
	
	/*
	//-- test mulblock;
	string blockXHex = "acbef20579b4b8ebce889bac8732dad7";
	//string blockXHex = "53";
	uint32_t xLen = blockXHex.size()/2;
	uint8_t blockX[xLen];
	stringToHex(blockXHex, blockX);
	
	string blockYHex = "522dc1f099567d07f47f37a32a84427d";
	//string blockYHex = "ca";
	uint32_t yLen = blockYHex.size()/2;
	uint8_t blockY[yLen];
	stringToHex(blockYHex, blockY);
	
	uint8_t blockZ[BLOCK_SIZE];
	printf("\nmulBlock X: ");
	printBuffer(blockX, BLOCK_SIZE);
	printf("\nmulBlock Y: ");
	printBuffer(blockY, BLOCK_SIZE);
	
	aesGCM->mulBlock(blockZ, blockX, blockY);
	
	printf("\nmulBlock result: ");
	printBuffer(blockZ, BLOCK_SIZE);
}
*/
