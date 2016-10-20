#ifndef EC_POINT_H
#define EC_POINT_H

	#include <gmp.h>

		class ECPoint{
		public:
			mpz_t x;
			mpz_t y;
			bool inf;
			
			ECPoint();
			ECPoint(const mpz_t* xpos, const mpz_t* ypos);
			ECPoint(const char* x_str, const char* y_str);
			~ECPoint();
		};

#endif

