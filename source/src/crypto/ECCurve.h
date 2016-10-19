#ifndef EC_CURVE_H
#define EC_CURVE_H

#include "EC_point.h"
#include <gmp.h>
#include <string.h>

class EC_curve
{
public:
	mpz_t p;
	mpz_t a4;
	mpz_t a6;
	mpz_t n;
	EC_point* g;
	
	//constructors
	EC_curve();
	EC_curve(const char* p, const char* n, const char* a4, const char* a6, const EC_point* g);

	//operations
	EC_point* add(const EC_point* P, const EC_point* Q);
	EC_point* mul(const EC_point* P, const mpz_t* k);
	EC_point* dbl(const EC_point* P);
	EC_point* opposite(const EC_point* P);
	bool contains(const EC_point* P);
	int getRequestSecurityLength();
	~EC_curve();

};

#endif // EC_CURVE_H
