#include "svc/SVC.h"
#include "svc/host/SVCHostIP.h"

class SendFileApp : SVCApp, SVCAuthenticator{

	SVC* svc;
	SVCEndPoint* endPoint;

	public:
		SendFileApp();
		~SendFileApp();
		
		string getAppID();	
		std::string getIdentity();
		bool verifyIdentity(std::string identity, std::string challenge, std::string proof);
		std::string generateProof(std::string challenge);
		std::string generateChallenge();
		
};

