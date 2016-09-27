#ifndef __SVC_AUTHENTICATOR__
#define __SVC_AUTHENTICATOR__

	#include <string>

	class SVCAuthenticator{

		public:
			SVCAuthenticator(){}
			virtual ~SVCAuthenticator(){}	
			virtual bool verify(std::string randomSecret, std::string challenge, std::string proof)=0;			
			virtual std::string generateChallenge(std::string randomSecret)=0;
			virtual std::string resolveChallenge(string challenge)=0;
			virtual std::string generateProof(std::string solution)=0;
			virtual std::string generateRandomSecret()=0;
	};

#endif
