#include "AES256.h"

#include <iostream>
using namespace std;

AES256::AES256(const uint8_t* key)
{
	this->aesKey = (uint8_t*)malloc(KEY_LENGTH);
	memcpy(this->aesKey, key, KEY_LENGTH);
	this->state = (uint8_t*)malloc(Nb<<2);
	keyExpansion();	
}

//--	UTILS METHODS		--//
uint32_t AES256::subWord(uint32_t word){
	uint32_t rs;
	uint8_t* p1 = (uint8_t*)&rs;
	uint8_t* p2 = (uint8_t*)&word;
	for (int i=0; i<4; i++){
		*(p1+i) = sbox[*(p2+i)];
	}
	return rs;
}

uint32_t AES256::rotWord(uint32_t word){
	uint32_t rs = word;
	rs = rs>>8;
	uint8_t r = *((uint8_t*)&word);
	uint8_t* p = (uint8_t*)&rs;
	*(p+3) = r;
	return rs;
}

void AES256::addRoundKey(int fromByte){
	uint8_t* p = (uint8_t*)&exKey[fromByte];
	for (int i=0;i<4;i++){
		for (int j=0;j<Nb;j++){
			state[i*Nb+j] ^= *(p+i*Nb+j);
		}
	}	
}

void AES256::subBytes(){
	for (int i=0;i<4;i++){
		for (int j=0;j<Nb;j++){
			state[i*Nb+j] = sbox[state[i*Nb+j]];
		}
	}
}

void AES256::shiftRows(){
	uint8_t t;
	for (int i=0;i<4;i++){	
		for (int r=0;r<i;r++){
			t = state[i];
			for (int j=0;j<Nb-1;j++){				
				state[i+j*4]=state[i+(j+1)*4];
			}
			state[i+(Nb-1)*4]=t;		
		}
	}
}

void AES256::mixColumns(){
	int r, c;
	uint8_t old[4];
	
	for(c=0;c<Nb;c++){
		for (r=0; r<4; r++){
			old[r]=state[r+c*4];
		}
		state[0+c*4] = mul02[old[0]] ^ mul03[old[1]] ^ old[2] ^ old[3];
		state[1+c*4] = old[0] ^ mul02[old[1]] ^ mul03[old[2]] ^ old[3];
		state[2+c*4] = old[0] ^ old[1] ^ mul02[old[2]] ^ mul03[old[3]];
		state[3+c*4] = mul03[old[0]] ^ old[1] ^ old[2] ^ mul02[old[3]];
	}
}

void AES256::invSubBytes(){
	for (int i=0;i<4;i++){
		for (int j=0;j<Nb;j++){
			state[i*Nb+j] = sboxInv[state[i*Nb+j]];
		}
	}
}

void AES256::invShiftRows(){
	uint8_t t;
	for (int i=0;i<4;i++){	
		for (int r=0;r<i;r++){
			t = state[i+(Nb-1)*4];
			for (int j=Nb-1;j>=1;j--){				
				state[i+j*4]=state[i+(j-1)*4];
			}
			state[i]=t;
		}
	}
}

void AES256::invMixColumns(){
	int r, c;
	uint8_t old[4];
	
	for(c=0;c<Nb;c++){
		for (r=0; r<4; r++){
			old[r]=state[r+c*4];
		}
		state[0+c*4] = mul0e[old[0]] ^ mul0b[old[1]] ^ mul0d[old[2]] ^ mul09[old[3]];
		state[1+c*4] = mul09[old[0]] ^ mul0e[old[1]] ^ mul0b[old[2]] ^ mul0d[old[3]];
		state[2+c*4] = mul0d[old[0]] ^ mul09[old[1]] ^ mul0e[old[2]] ^ mul0b[old[3]];
		state[3+c*4] = mul0b[old[0]] ^ mul0d[old[1]] ^ mul09[old[2]] ^ mul0e[old[3]];
	}
}

//--	PRIVATE METHODS		--//
void AES256::keyExpansion(){
	cout<<"\nAES key:\n";
	printBuffer(this->aesKey, KEY_LENGTH);
	
	int exKeyLen = Nb*(Nr+1);
	this->exKey = (uint32_t*)malloc(exKeyLen*4);
	
	uint32_t temp;
	int i;
	
	for (i=0; i<Nk; i++){
		exKey[i] = *((uint32_t*)(this->aesKey+i*4));
	}
		
	for (i=Nk; i<exKeyLen; i++){
		temp = exKey[i-1];
		if (i%Nk == 0){
			temp = subWord(rotWord(temp)) ^ rCon[i/Nk];
		}
		else if (i%Nk == 4){
			temp = subWord(temp);
		}
		exKey[i] = exKey[i-Nk] ^ temp;
	}
}

void AES256::encryptBlock(const uint8_t* blockin, uint8_t* blockout){	
	//--	copy blockin to state
	for (int i=0;i<4;i++){
		for (int j=0;j<Nb;j++){
			state[i*Nb+j] = blockin[i*Nb+j];
		}
	}
	//printf("\nEncryption block:\n");
	//printBuffer(state, 4*Nb);

	//--	aes algorithm
	addRoundKey(0);
	//printBuffer(state, 4*Nb);
	
	for (int round = 1; round<Nr; round++){
		subBytes();
		//printBuffer(state, 4*Nb);
		shiftRows();
		//printBuffer(state, 4*Nb);
		mixColumns();
		//printBuffer(state, 4*Nb);
		addRoundKey(round*Nb);
		//printBuffer(state, 4*Nb);	
	}
	
	subBytes();
	//printBuffer(state, 4*Nb);
	shiftRows();
	//printBuffer(state, 4*Nb);
	addRoundKey(Nr*Nb);
	//printBuffer(state, 4*Nb);

	//--	copy state to blockout
	for (int i=0;i<4;i++){
		for (int j=0;j<Nb;j++){
			blockout[i*Nb+j] = state[i*Nb+j];
		}
	}
}

void AES256::decryptBlock(const uint8_t* blockin, uint8_t* blockout){
	//--	copy blockin to state
	for (int i=0;i<4;i++){
		for (int j=0;j<Nb;j++){
			state[i*Nb+j] = blockin[i*Nb+j];
		}
	}
	
	//printf("\nDecryption block:\n");
	//printBuffer(state, 4*Nb);
	
	//--	invert aes algorithm
	addRoundKey(Nr*Nb);
	//printBuffer(state, 4*Nb);
	for (int round = Nr-1; round>=1; round--){		
		invShiftRows();
		//printBuffer(state, 4*Nb);
		invSubBytes();
		//printBuffer(state, 4*Nb);
		addRoundKey(round*Nb);
		//printBuffer(state, 4*Nb);
		invMixColumns();
		//printBuffer(state, 4*Nb);
	}
	
	invShiftRows();
	//printBuffer(state, 4*Nb);
	invSubBytes();
	//printBuffer(state, 4*Nb);
	addRoundKey(0);
	//printBuffer(state, 4*Nb);
	
	//--	copy state to blockout
	for (int i=0;i<4;i++){
		for (int j=0;j<Nb;j++){
			blockout[i*Nb+j] = state[i*Nb+j];
		}
	}
}
//----------------------------//

void AES256::encrypt(const uint8_t* data, uint32_t dataLen, uint8_t** encrypted, uint32_t* encryptedLen){
	*encryptedLen = dataLen%BLOCK_SIZE>0? dataLen + BLOCK_SIZE - dataLen%BLOCK_SIZE : dataLen;
	
	//--	copy data to encrypted
	*encrypted = (uint8_t*)malloc(*encryptedLen);
	memset(*encrypted, 0, *encryptedLen);
	memcpy(*encrypted, data, dataLen);

	//--	encrypt data, block by block
	int blockNum = *encryptedLen/(BLOCK_SIZE);
	for (int i = 0; i<blockNum; i++){
		encryptBlock(*encrypted+i*(BLOCK_SIZE), *encrypted+i*(BLOCK_SIZE));
	}
}

bool AES256::decrypt(const uint8_t* encrypted, uint32_t encryptedLen, uint8_t** data, uint32_t* dataLen){
	if (encryptedLen<=0 || encryptedLen%BLOCK_SIZE>0){
		return false;
	}
	else{
		//--	copy encrypted to data to process
		*dataLen = encryptedLen;
		*data = (uint8_t*)malloc(*dataLen);	
		memcpy(*data, encrypted, encryptedLen);
		
		//--	reverse the encryption process
		int blockNum = encryptedLen/BLOCK_SIZE;
		for (int i = 0; i<blockNum; i++){
			decryptBlock(*data+i*BLOCK_SIZE, *data+i*BLOCK_SIZE);
		}

		return true;
	}	
}


AES256::~AES256(){
	memset(this->aesKey, 0, KEY_LENGTH);
	memset(this->state, 0, 4*Nb);
	memset(this->exKey, 0, Nb*(Nr+1)*4);
	delete this->aesKey;
	delete this->state;	
	delete this->exKey;
}

/*
int main(int argc, char** argv){
	string keyHexString = "E3C08A8F06C6E3AD95A70557B23F75483CE33021A9C72B7025666204C69C0B72";
	uint8_t key[KEY_LENGTH];
	stringToHex(keyHexString, key);
	AES256* aes256 = new AES256(key);
	
	
	string dataString = "12153524C0895E81B2C2846500000001";
	uint32_t dataLen = dataString.size()/2;
	uint8_t data[dataLen];
	stringToHex(dataString, data);
	
	
	uint8_t* encrypted;
	uint32_t encryptedLen;
	
	uint8_t* decrypted;	
	uint32_t decryptedLen;
	
	printf("\nInmain: Data:\n");
	printBuffer(data, dataLen);

	aes256->encrypt(data, dataLen, &encrypted, &encryptedLen);
	printf("\nInmain: Encrypted data:\n");
	printBuffer(encrypted, encryptedLen);
	
	aes256->decrypt(encrypted, encryptedLen, &decrypted, &decryptedLen);
	printf("\nInmain: Decrypted data:\n");
	printBuffer(decrypted, decryptedLen);
	
	delete encrypted;
	delete decrypted;
	return 0;
}*/


