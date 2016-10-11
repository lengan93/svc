#ifndef __SVC_AUTHENTICATOR_PKI__
#define __SVC_AUTHENTICATOR_PKI__

	#include "SVCAuthenticator.h"
	#include "../../crypto/crypto-utils.h"
	#include "../../crypto/AESGCM.h"
	#include "../../crypto/SHA256.h"
	#include "../../crypto/crypto-utils.h"

	class SVCAuthenticatorSharedSecret : SVCAuthenticator{
			
		static const int HASH_TIME = 10;
				
		AESGCM* aesGCM;
		SHA256* sha256;
		
		private:
			std::string challenge;
			std::string solution;

		public:
			static const std::string NULL_STRING;
			
			SVCAuthenticatorSharedSecret(std::string secretPath);
			virtual ~SVCAuthenticatorSharedSecret();
			
			//--	inherited interface
			virtual std::string generateChallenge()=0;
			virtual std::string resolveChallenge(std::string challenge)=0;
			virtual std::string generateProof()=0;
			virtual bool verify(std::string proof)=0;	
	};

#endif
