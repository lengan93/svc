#ifndef __SVC_AUTHENTICATOR__
#define __SVC_AUTHENTICATOR__

	#include <string>

	class SVCAuthenticator{

		public:
			SVCAuthenticator(){}
			virtual ~SVCAuthenticator(){}
			
			virtual std::string generateChallenge()=0;
			virtual std::string resolveChallenge(std::string challenge)=0;
			virtual std::string generateProof()=0;
			virtual bool verify(std::string proof)=0;			
	};

#endif
