#ifndef EC_POINT
#define EC_POINT

#include <gmp.h>

	class EC_point{
	public:
		mpz_t x;
		mpz_t y;
		bool inf;
		
		EC_point();
		EC_point(const mpz_t* xpos, const mpz_t* ypos);
		EC_point(char* x_str, char* y_str);
		~EC_point();

	};

#endif

