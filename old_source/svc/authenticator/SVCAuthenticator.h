#ifndef __SVC_AUTHENTICATOR__

#define __SVC_AUTHENTICATOR__

#include <string>

class SVCAuthenticator{

	public:
		SVCAuthenticator(){}
		virtual ~SVCAuthenticator(){}
		virtual std::string getIdentity()=0;
		virtual bool verifyIdentity(std::string identity, std::string challenge, std::string proof)=0;
		virtual std::string generateProof(std::string challenge)=0;
		virtual std::string generateChallenge()=0;
};

#endif
