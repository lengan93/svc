#include "SVCAuthenticatorPKI.h"

using namespace std;

SVCAuthenticatorPKI::SVCAuthenticatorPKI(string caPath, string certpath, string keyPath){
}

SVCAuthenticatorPKI::~SVCAuthenticatorPKI(){
}

bool SVCAuthenticatorPKI::verify(std::string randomSecret, std::string challenge, std::string proof){
}

string SVCAuthenticatorPKI::generateRandomSecret(){
}

string SVCAuthenticatorPKI::generateChallenge(std::string randomSecret){
}

string SVCAuthenticatorPKI::resolveChallenge(string challenge){
}

string SVCAuthenticatorPKI::generateProof(std::string solution){
}
