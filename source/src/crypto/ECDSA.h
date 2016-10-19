#ifndef ECDSA
#define ECDSA

	#include "CE_curve.h"
	#include "CE_point.h"
	#include "sha256.h"
	#include "utils.h"

	class ECDSA{
		
	private:
		EC_curve* curve;
		EC_point* pubKey;
		mpz_t* priKey;
		
	public:
		ECDSA();
		ECDSA(EC_curve* curve, EC_point* pubKey, mpz_t* priKey);
		int generateSignature(const char* message, char* signature);
		bool verifySignature(const char* messages, const char* signature);
		~ECDSA();
	};

#endif
