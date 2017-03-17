#include "SVCAuthenticatorSharedSecret.h"

const std::string SVCAuthenticatorSharedSecret::NULL_STRING = "";

SVCAuthenticatorSharedSecret::SVCAuthenticatorSharedSecret(std::string secretPath){	
	//-- read shared secret in hex std::string format
	uint8_t sharedKey[KEY_LENGTH] = "";
	std::ifstream key(secretPath);
	std::stringstream buffer;
	buffer << key.rdbuf();
	
	//printf("\nread shared secret: %s", buffer.str().c_str());
	
	//-- convert form hex to binary form	
	utils::stringToHex(buffer.str().c_str(), sharedKey);
	
	//-- create aesgcm and hash instances
	this->aesGCM = new AESGCM(sharedKey, SECU_128);
	this->sha256 = new SHA256();
}

SVCAuthenticatorSharedSecret::~SVCAuthenticatorSharedSecret(){
	delete this->aesGCM;
	delete this->sha256;
}

std::string SVCAuthenticatorSharedSecret::getRemoteIdentity(const std::string& challengeSecret){
	return "";
}

std::string SVCAuthenticatorSharedSecret::generateChallenge(const std::string& challengeSecret){
	std::string rs;
	//-- random iv std::string
	uint16_t ivLen = KEY_LENGTH;
	uint8_t iv[ivLen];
	crypto::generateRandomData(ivLen, iv);
	//-- encrypt this std::string with aesgcm, shared key
	uint32_t encryptedLen;
	uint8_t* encrypted;
	uint8_t* tag;
	uint16_t tagLen;

	this->aesGCM->encrypt(iv, ivLen, (uint8_t*)challengeSecret.c_str(), challengeSecret.size(), NULL, 0, &encrypted, &encryptedLen, &tag, &tagLen);
	uint32_t challengeLen = 8 + encryptedLen + ivLen + tagLen;
	uint8_t* challengeBuf = (uint8_t*)malloc(challengeLen);
	
	uint8_t* p = challengeBuf;
	memcpy(p, &encryptedLen, 4);
	p+=4;
	memcpy(p, encrypted, encryptedLen);	
	p+=encryptedLen;
	
	memcpy(p, &ivLen, 2);
	p+=2;
	memcpy(p, iv, ivLen);
	p+=ivLen;
	
	memcpy(p, &tagLen, 2);
	p+=2;
	memcpy(p, tag, tagLen);
	rs = utils::hexToString(challengeBuf, challengeLen);
	
	//-- clear then return
	free(encrypted);
	free(tag);
	free(challengeBuf);
	return rs;
}

std::string SVCAuthenticatorSharedSecret::resolveChallenge(const std::string& challenge){
	std::string rs;
	
	uint8_t* challengeBuf = (uint8_t*)malloc(SVC_DEFAULT_BUFSIZ);
	uint32_t challengeLen = utils::stringToHex(challenge, challengeBuf);
	
	uint8_t* iv;
	uint16_t ivLen;
	
	uint8_t* encrypted;
	uint8_t* tag;
	uint16_t tagLen;
	uint8_t* p = challengeBuf;
	uint8_t* challengeSecret;
	uint32_t challengeSecretLen;
	
	if (challengeLen>0){		
		encrypted = p+4;
		uint32_t encryptedLen = *((uint32_t*)p);
		p += 4 + encryptedLen;
		
		iv = p+2;
		ivLen = *((uint16_t*)p);
		p += 2 + ivLen;
		
		tag = p+2;
		tagLen = *((uint16_t*)p);
				
		if (this->aesGCM->decrypt(iv, ivLen, encrypted, encryptedLen, NULL, 0, tag, tagLen, &challengeSecret, &challengeSecretLen)){
			rs = std::string((char*)challengeSecret, challengeSecretLen);
			free(challengeSecret);
		}
		else{			
			rs = NULL_STRING;
		}		
	}
	else{
		rs = NULL_STRING;
	}	
	free(challengeBuf);
	return rs;
}

std::string SVCAuthenticatorSharedSecret::generateProof(const std::string& challengeSecret){
	//-- hash the solution HASH_TIME times
	std::string rs;
	uint8_t hashBuffer[SHA256::DIGEST_SIZE];
	if (challengeSecret.size()>0){		
		this->sha256->hash(challengeSecret.c_str(), challengeSecret.size(), hashBuffer);
		rs = utils::hexToString(hashBuffer, SHA256::DIGEST_SIZE);
	}
	else{
		rs = NULL_STRING;
	}
	return rs;
}

bool SVCAuthenticatorSharedSecret::verifyProof(const std::string& challengeSecret, const std::string& proof){
	std::string comparison;
	if (proof.size()>0){
		uint8_t proofBuffer[SHA256::DIGEST_SIZE];
		uint32_t len = utils::stringToHex(proof, proofBuffer);
		uint8_t hashBuffer[SHA256::DIGEST_SIZE];
		this->sha256->hash(challengeSecret.c_str(), challengeSecret.size(), hashBuffer);
		return (memcmp(proofBuffer, hashBuffer, SHA256::DIGEST_SIZE) == 0);
	}
	else{
		return false;
	}
}

