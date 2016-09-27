#include "SVCAuthenticatorSimple.h"
#include <cstdlib>
#include <algorithm>
#include <iostream>
#include <fstream>

using namespace std;

string SVCAuthenticatorSharedSecret::randomStrGen(int length) {	
    static string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    string result;
    result.resize(length);
    
    for (int i = 0; i < length; i++)
        result[i] = charset[rand() % charset.length()];
    return result;
}

SVCAuthenticatorSharedSecret::SVCAuthenticatorSharedSecret(string secretPath){	
	//--	load shared secret from file
	ifstream fileStream;
	fileStream.open(secretPath, ios::binary);
	if (fileStream.is_open()){
		//--	read shared secret
		this->sharedKey = (uint8_t*)malloc(KEY_LENGTH>>3);
		fileStream.read((char*)this->sharedKey, KEY_LENGTH>>3);
		//--	construct AES-GCM for encrypt/derypt
	}
	else{
		//--	throw exception
		throw "Cannot read from file";
	}	
}

SVCAuthenticatorSharedSecret::~SVCAuthenticatorSharedSecret(){	
}

bool SVCAuthenticatorSharedSecret::verify(string randomSecret, string challenge, string proof){
	return (hasher(randomSecret) == hasher(proof));
}

string SVCAuthenticatorSharedSecret::generateRandomSecret(){
	return randomStrGen(RANDOM_LENGTH);
}

string SVCAuthenticatorSharedSecret::generateChallenge(string randomSecret){
	return reverse(randomSecret.begin(), randomSecret.end());
}

string SVCAuthenticatorSharedSecret::resolveChallenge(string challenge){
	return reverse(challenge.begin(), challenge.end());
}

string SVCAuthenticatorSharedSecret::generateProof(string solution){
	return hasher(solution);
}
