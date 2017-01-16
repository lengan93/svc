/* Secure Virtual Connector (SVC) API header */

#ifndef __SVC__
#define __SVC__

#include <time.h>

#include "../src/svc/SVC.h"
#include "../src/svc/host/SVCHostIP.h"
#include "../src/svc/authenticator/SVCAuthenticatorSharedSecret.h"

#include "../src/utils/PeriodicWorker.h"

class Connector {

	private :

		std::string appID;
		SVCHost* remoteHost;
		SVCAuthenticatorSharedSecret* authenticator;
		SVCEndpoint* endpoint;

		int GetFileSize(std::string filename);

		float timeDistance(const struct timespec* greater, const struct timespec* smaller)

	public :

		Connector(std::string remoteHost);

		Connector(std::string appID, std::string remoteHost, SVCAuthenticatorSharedSecret* authenticator);

		~Connector();

		int sendFile(std::string filename);
}

#endif
