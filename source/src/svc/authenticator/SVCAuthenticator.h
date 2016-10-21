#ifndef __SVC_AUTHENTICATOR__
#define __SVC_AUTHENTICATOR__

	#include <string>
	#include "../../crypto/crypto-utils.h"
	
	#define MINIMUM_SECURITY_LENGTH 64

	class SVCAuthenticator{

		public:
			SVCAuthenticator(){}
			virtual ~SVCAuthenticator(){}
			
			virtual std::string generateChallengeSecret(){
				uint8_t* randomData = (uint8_t*)malloc(MINIMUM_SECURITY_LENGTH);
				generateRandomData(MINIMUM_SECURITY_LENGTH, randomData);
				return hexToString(randomData, MINIMUM_SECURITY_LENGTH);
			}
			virtual std::string generateChallenge(const std::string& challengeSecret)=0;			
			virtual std::string resolveChallenge(const std::string& challenge)=0;
			virtual std::string generateProof(const std::string& challengeSecret)=0;
			virtual bool verifyProof(const std::string& challengeSecret, const std::string& proof)=0;
	};

#endif
