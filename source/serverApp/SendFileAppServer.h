#include "../src/svc/authenticator/SVCAuthenticator.h"
#include "../src/svc/SVC.h"

class SendFileAppServer : SVCAuthenticator{

	public:
		SendFileAppServer();	
		~SendFileAppServer();
		//--	inherited interfaces
		std::string getIdentity();
		bool verifyIdentity(std::string identity, std::string challenge, std::string proof);
		std::string generateProof(std::string challenge);
		std::string generateChallenge();
		
};
