#include "SVCAuthenticatorSharedSecret.h"
#include <iostream>
#include <fstream>
#include <sstream>

using namespace std;

const string SVCAuthenticatorSharedSecret::NULL_STRING = "";

SVCAuthenticatorSharedSecret::SVCAuthenticatorSharedSecret(string secretPath){	
	//-- read shared secret in hex string format
	uint8_t* sharedKey;
	ifstream key(secretPath);
	stringstream buffer;
	buffer << key.rdbuf();
	
	//-- convert form hex to binary form	
	stringToHex(buffer.str(), &sharedKey);
	
	//-- create aesgcm and hash instances
	this->aesGCM = new AESGCM(sharedKey, SECU_128);
	this->sha256 = new SHA256();
	delete sharedKey;
	this->solution = NULL_STRING;
	this->challenge = NULL_STRING;
}

SVCAuthenticatorSharedSecret::~SVCAuthenticatorSharedSecret(){	
}

string SVCAuthenticatorSharedSecret::generateChallenge(){
	string rs;
	
	//-- random a string
	uint8_t* randomData = (uint8_t*)malloc(KEY_LENGTH);
	generateRandomData(KEY_LENGTH, randomData);
	//-- random iv string
	uint8_t* iv = (uint8_t*)malloc(KEY_LENGTH);
	generateRandomData(KEY_LENGTH, iv);
	//-- encrypt this string with aesgcm, shared key
	uint32_t encryptedLen;
	uint8_t* encrypted;
	uint8_t* tag;
	uint32_t tagLen;

	this->aesGCM->encrypt(iv, KEY_LENGTH, randomData, KEY_LENGTH, NULL, 0, &encrypted, &encryptedLen, &tag, &tagLen);
	uint32_t challengeLen = KEY_LENGTH*2 + tagLen;
	uint8_t* challengeBuf = (uint8_t*)malloc(challengeLen);
	memcpy(challengeBuf, encrypted, KEY_LENGTH);
	memcpy(challengeBuf, iv, KEY_LENGTH);
	memcpy(challengeBuf, tag, tagLen);
	this->challenge = hexToString(randomData, KEY_LENGTH); //-- save this to verify later
	rs = hexToString(challengeBuf, challengeLen);
	
	//-- clear then return
	delete randomData;
	delete iv;
	delete encrypted;
	delete tag;
	delete challengeBuf;
	return rs;
}

string SVCAuthenticatorSharedSecret::resolveChallenge(string challenge){
	string rs;
	//-- un-hex the challenge
	uint8_t* challengeBuf;
	uint32_t challengeLen = stringToHex(challenge, &challengeBuf);
	
	if (challengeLen>0){
		//-- 
		uint8_t* randomData;
		uint32_t dataLen;
		if (this->aesGCM->decrypt(challengeBuf+KEY_LENGTH, KEY_LENGTH, challengeBuf, KEY_LENGTH, NULL, 0, challengeBuf+2*KEY_LENGTH, SECU_128>>3, &randomData, &dataLen)){
			rs = hexToString(randomData, dataLen);
			this->solution = string(rs);
		}
		else{			
			rs = NULL_STRING;
		}
		//-- clear memory
		delete challengeBuf;
		delete randomData;
	}
	else{
		rs = NULL_STRING;
	}	
	return rs;
}

string SVCAuthenticatorSharedSecret::generateProof(){
	//-- hash the solution HASH_TIME times
	string rs;
	if (this->solution!=NULL_STRING){		
		for (int i=0; i<HASH_TIME; i++){
			rs = this->sha256->hash(solution);
		}		
	}
	else{
		rs = NULL_STRING;
	}
	return rs;
}

bool SVCAuthenticatorSharedSecret::verify(string proof){
	string comparison;
	if (proof!=NULL_STRING){
		for (int i=0; i<HASH_TIME; i++){
			comparison = this->sha256->hash(proof);
		}
		return (comparison == this->challenge);
	}
	else{
		return false;
	}
}

