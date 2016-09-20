#ifndef __SVC_APP__

#define __SVC_APP__

#include <string>

class SVCApp{
	public:
		SVCApp(){}
		virtual ~SVCApp(){}
		virtual std::string getAppID()=0;
		//virtual bool isServer()=0;
};

#endif
