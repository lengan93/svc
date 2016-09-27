#ifndef __SVC_AUTHENTICATOR_PKI__
#define __SVC_AUTHENTICATOR_PKI__

	#include "SVCAuthenticator.h"
	
	#define KEY_LENGTH 256

	class SVCAuthenticatorSharedSecret : SVCAuthenticator{
		
		uint8_t* sharedKey;
		
		private:
			std::string randomStrGen(int length);
	
		public:
			SVCAuthenticatorSharedSecret(string secretPath);
			virtual ~SVCAuthenticatorSharedSecret();
			
			virtual bool verify(std::string randomSecret, std::string challenge, std::string proof);
			virtual std::string generateRandomSecret();
			virtual std::string generateChallenge(std::string randomSecret);
			virtual std::string resolveChallenge(string challenge);
			virtual std::string generateProof(std::string solution);
	}

#endif
