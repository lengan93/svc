#ifndef __SVC_HOST__

#define __SVC_HOST__

#include <string>

class SVCHost{
	
	public:
		SVCHost(){}
		virtual ~SVCHost(){};
		virtual uint32_t getHostAddress()=0;
};

#endif
