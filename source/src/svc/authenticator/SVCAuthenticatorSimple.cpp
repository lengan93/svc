#include "SVCAuthenticatorSimple.h"
#include <cstdlib>
#include <algorithm>

using namespace std;

string SVCAuthenticatorSimple::randomStrGen(int length) {	
    static string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    string result;
    result.resize(length);
    
    for (int i = 0; i < length; i++)
        result[i] = charset[rand() % charset.length()];
    return result;
}

SVCAuthenticatorSimple::SVCAuthenticatorSimple(){	
	srand(time(NULL));
}

SVCAuthenticatorSimple::~SVCAuthenticatorSimple(){	
}

bool SVCAuthenticatorSimple::verify(string randomSecret, string challenge, string proof){
	return (hasher(randomSecret) == hasher(proof));
}

string SVCAuthenticatorSimple::generateRandomSecret(){
	return randomStrGen(RANDOM_LENGTH);
}

string SVCAuthenticatorSimple::generateChallenge(string randomSecret){
	return reverse(randomSecret.begin(), randomSecret.end());
}

string SVCAuthenticatorSimple::resolveChallenge(string challenge){
	return reverse(challenge.begin(), challenge.end());
}

string SVCAuthenticatorSimple::generateProof(string solution){
	return hasher(solution);
}
