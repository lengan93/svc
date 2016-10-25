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
	
	//printf("\nread shared secret: %s", buffer.str().c_str());
	
	//-- convert form hex to binary form	
	stringToHex(buffer.str().c_str(), &sharedKey);
	
	//-- create aesgcm and hash instances
	this->aesGCM = new AESGCM(sharedKey, SECU_128);
	this->sha256 = new SHA256();
	delete sharedKey;
}

SVCAuthenticatorSharedSecret::~SVCAuthenticatorSharedSecret(){	
}

string SVCAuthenticatorSharedSecret::generateChallenge(const string& challengeSecret){
	string rs;
	//-- random iv string
	uint32_t ivLen = KEY_LENGTH;
	uint8_t* iv = (uint8_t*)malloc(ivLen);
	generateRandomData(ivLen, iv);
	//-- encrypt this string with aesgcm, shared key
	uint32_t encryptedLen;
	uint8_t* encrypted;
	uint8_t* tag;
	uint32_t tagLen;

	this->aesGCM->encrypt(iv, ivLen, (uint8_t*)challengeSecret.c_str(), challengeSecret.size(), NULL, 0, &encrypted, &encryptedLen, &tag, &tagLen);
	uint32_t challengeLen = 12 + encryptedLen + ivLen + tagLen;
	uint8_t* challengeBuf = (uint8_t*)malloc(challengeLen);
	
	uint8_t* p = challengeBuf;
	memcpy(p, (uint32_t*)&encryptedLen, 4);
	p+=4;
	memcpy(p, encrypted, encryptedLen);
	p+=encryptedLen;
	memcpy(p, (uint32_t*)&ivLen, 4);
	p+=4;
	memcpy(p, iv, ivLen);
	p+=ivLen;
	memcpy(p, (uint32_t*)&tagLen, 4);
	p+=4;
	memcpy(p, tag, tagLen);
	rs = hexToString(challengeBuf, challengeLen);
	
	//-- clear then return	
	delete iv;
	delete encrypted;
	delete tag;
	delete challengeBuf;
	return rs;
}

string SVCAuthenticatorSharedSecret::resolveChallenge(const std::string& challenge){
	string rs;
	//-- un-hex the challenge
	uint8_t* challengeBuf;
	uint32_t challengeLen = stringToHex(challenge, &challengeBuf);
	
	if (challengeLen>0){
		//--
		uint8_t* iv;
		uint8_t* encrypted;
		uint8_t* tag;
		uint8_t* p =challengeBuf;
		uint8_t* challengeSecret;
		uint32_t challengeSecretLen;
		
		encrypted = p+4;
		uint32_t encryptedLen = *((uint32_t*)p);
		p += 4 + encryptedLen;
		
		iv = p+4;
		uint32_t ivLen = *((uint32_t*)p);
		p += 4 + ivLen;
		
		tag = p+4;
		uint32_t tagLen = *((uint32_t*)p);
				
		if (this->aesGCM->decrypt(iv, ivLen, encrypted, encryptedLen, NULL, 0, tag, tagLen, &challengeSecret, &challengeSecretLen)){
			rs = string((char*)challengeSecret, challengeSecretLen);
			delete challengeSecret;			
		}
		else{			
			rs = NULL_STRING;
		}
		//-- clear memory
		delete challengeBuf;		
	}
	else{
		rs = NULL_STRING;
	}	
	return rs;
}

string SVCAuthenticatorSharedSecret::generateProof(const string& challengeSecret){
	//-- hash the solution HASH_TIME times
	string rs;
	if (challengeSecret.size()>0){		
		for (int i=0; i<HASH_TIME; i++){
			rs = this->sha256->hash(challengeSecret);
		}
	}
	else{
		rs = NULL_STRING;
	}
	return rs;
}

bool SVCAuthenticatorSharedSecret::verifyProof(const string& challengeSecret, const string& proof){
	string comparison;
	if (proof.size()>0){
		for (int i=0; i<HASH_TIME; i++){
			comparison = this->sha256->hash(challengeSecret);
		}
		return (comparison == proof);
	}
	else{
		return false;
	}
}

