#ifndef __SVC_AUTHENTICATOR_PKI__
#define __SVC_AUTHENTICATOR_PKI__

	//#include <iostream>
	#include <fstream>
	#include <sstream>

	#include "SVCAuthenticator.h"
	#include "../../crypto/AESGCM.h"
	#include "../../crypto/SHA256.h"

	class SVCAuthenticatorSharedSecret : public SVCAuthenticator{
			
		static const int HASH_TIME = 10;
				
		AESGCM* aesGCM;
		SHA256* sha256;

		public:
			static const std::string NULL_STRING;
			
			SVCAuthenticatorSharedSecret(std::string secretPath);
			virtual ~SVCAuthenticatorSharedSecret();
			
			//--	inherited interface
			std::string generateChallenge(const std::string& challengeSecret);			
			std::string resolveChallenge(const std::string& challenge);
			std::string getRemoteIdentity(const std::string& challengeSecret);
			std::string generateProof(const std::string& challengeSecret);
			bool verifyProof(const std::string& challengeSecret, const std::string& proof);
	};

#endif
