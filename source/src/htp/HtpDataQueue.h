/* 
	Author: Immort
	This queue is implemented to be generic and thread-safe
*/

#ifndef __HTP_DATA_QUEUE__
#define __HTP_DATA_QUEUE__

	#include <cstdint>

	using namespace std;

	template <class T>
	class HtpDataQueue{
		private:
			uint16_t size;
			
		public:
	
			HtpDataQueue(uint16_t size){
				this->size = size;
			}
		
			~HtpDataQueue(){
				
			}
	};

#endif
	
