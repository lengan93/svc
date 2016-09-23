#include "../src/svc/SVC.h"
#include "../src/svc/host/SVCHostIP.h"

class SendFileApp : SVCAuthenticator{

	SVC* svc;
	SVCEndPoint* endPoint;

	public:
		SendFileApp();
		~SendFileApp();
		
		std::string getIdentity();
		bool verifyIdentity(std::string identity, std::string challenge, std::string proof);
		std::string generateProof(std::string challenge);
		std::string generateChallenge();
		
};

