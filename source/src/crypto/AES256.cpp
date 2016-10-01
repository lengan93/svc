#include "AES256.h"

#include <iostream>
using namespace std;

AES256::AES256(const uint8_t* key)
{
	this->aesKey = (uint8_t*)malloc(KEY_LENGTH>>3);
	memcpy(this->aesKey, key, KEY_LENGTH>>3);	
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

void AES256::addRoundKey(uint8_t* state, int fromByte){
	uint8_t* p = (uint8_t*)&exKey[fromByte>>2];
	for (int i=0;i<4;i++){
		for (int j=0;j<Nb;j++){
			state[i*Nb+j] ^= *(p+Nb-1-j);
		}
	}	
}

void AES256::subBytes(uint8_t* state){
	for (int i=0;i<4;i++){
		for (int j=0;j<Nb;j++){
			state[i*Nb+j] = sbox[state[i*Nb+j]];
		}
	}
}

void AES256::shiftRows(uint8_t* state){
	uint8_t t;
	for (int i=0;i<4;i++){	
		for (int r=0;r<i;r++){
			t = state[i*Nb];
			for (int j=0;j<Nb-1;j++){				
				state[i*Nb+j]=state[i*Nb+j+1];
			}
			state[i*Nb+Nb-1]=t;		
		}
	}
}

void AES256::mixColumns(uint8_t* state){
	int i;
	uint8_t tmp,tm,t;
	for(i=0;i<Nb;i++)
	{	
		t=state[i];
		tmp = state[i] ^ state[Nb+i] ^ state[2*Nb+i] ^ state[3*Nb+i] ;
		tm = state[i] ^ state[Nb+i]; tm = xtime(tm); state[i] ^= tm ^ tmp;
		tm = state[Nb+i] ^ state[2*Nb+i]; tm = xtime(tm); state[Nb+i] ^= tm ^ tmp;
		tm = state[2*Nb+i] ^ state[3*Nb+i]; tm = xtime(tm); state[2*Nb+i] ^= tm ^ tmp;
		tm = state[3*Nb+i] ^ t; tm = xtime(tm); state[3*Nb+i] ^= tm ^ tmp;
	}
}

//--	PRIVATE METHODS		--//
void AES256::keyExpansion(){
	this->exKey = (uint32_t*)malloc(Nb*(Nr+1));
	
	uint32_t temp;
	int i;
	int exKeyLen = Nb*(Nr+1);
	
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
	uint8_t* state = (uint8_t*)malloc(4*Nb);
	//--	copy blockin to state
	for (int i=0;i<4;i++){
		for (int j=0;j<Nb;j++){
			state[i*Nb+j] = blockin[i*Nb+j];
		}
	}
	addRoundKey(state, 0);
	for (int round = 1; round<=Nr; round++){
		subBytes(state);
		shiftRows(state);
		if (round<Nr) mixColumns(state);
		addRoundKey(state, round*Nb);		
	}	
	//--	copy state to blockout
	for (int i=0;i<4;i++){
		for (int j=0;j<Nb;j++){
			blockout[i*Nb+j] = state[i*Nb+j];
		}
	}
	delete state;
}
//----------------------------//

void AES256::encrypt(const uint8_t* data, size_t dataLen, uint8_t** encrypted, size_t* encryptedLen){
	*encryptedLen = dataLen%(BLOCK_SIZE>>3)>0? dataLen + (BLOCK_SIZE>>3) - dataLen%(BLOCK_SIZE>>3) : dataLen;
	//cout<<"Data size: "<<data.size()<<" & Padded len: "<<encryptedLen<<endl;
	*encrypted = (uint8_t*)malloc(*encryptedLen);
	memset(*encrypted, 0, *encryptedLen);
	memcpy(*encrypted, data, dataLen);

	cout<<"paddedData: ";
	printBuffer(*encrypted, *encryptedLen);	

	//--	encrypt data, block by block
	for (int i = 0; i<*encryptedLen/(BLOCK_SIZE>>3); i++){
		encryptBlock(*encrypted+i*(BLOCK_SIZE>>3), *encrypted+i*(BLOCK_SIZE>>3));
	}	
}

bool decrypt(const uint8_t* encrypted, size_t encryptedLen, uint8_t** data, size_t* dataLen){
	return true;	
}

AES256::~AES256(){
	delete this->aesKey;
	delete this->exKey;
}

int main(int argc, char** argv){
	string keyHexString = "43A4A0B1D37087237BD6FE918E5D2E57B61076A93979BC996120ABD6D6CAD57E";
	uint8_t key[KEY_LENGTH];
	stringToHex(keyHexString, key);
	AES256* aes256 = new AES256(key);


	string data = "These are some data";
	cout<<"Input data to be encrypted: ";
	cin>>data;
	uint8_t* encrypted;
	size_t encryptedLen;
	aes256->encrypt((uint8_t*)data.c_str(), data.size(), &encrypted, &encryptedLen);
	
	printf("encrypted data, hex: ");
	printBuffer(encrypted, encryptedLen);
	return 0;
}

