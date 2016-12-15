#ifndef __SVC_HOST__
#define __SVC_HOST__

	class SVCHost{
		
		public:
			SVCHost(){}
			virtual ~SVCHost(){};
			virtual uint32_t getHostAddress()=0;
			virtual std::string getAppID()=0;
	};

#endif
