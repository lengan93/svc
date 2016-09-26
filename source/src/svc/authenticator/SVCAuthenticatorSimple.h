#ifndef __SVC_AUTHENTICATOR_PKI__
#define __SVC_AUTHENTICATOR_PKI__

	#include "SVCAuthenticator.h"
	
	#define RANDOM_LENGTH 256

	class SVCAuthenticatorSimple : SVCAuthenticator{
		
		static hasher<string> hasher;		
		
		private:
			std::string randomStrGen(int length);		
	
		public:
			SVCAuthenticatorSimple();
			virtual ~SVCAuthenticatorSimple();
			
			virtual bool verify(std::string randomSecret, std::string challenge, std::string proof);
			virtual std::string generateRandomSecret();
			virtual std::string generateChallenge(std::string randomSecret);
			virtual std::string resolveChallenge(string challenge);
			virtual std::string generateProof(std::string solution);
	}

#endif
