#include "ECDSA.h"

ECDSA::ECDSA()
{
}

ECDSA::ECDSA(EC_curve* curve, EC_point* pubKey, mpz_t* priKey){
	this->curve = curve;
	this->pubKey = pubKey;
	this->priKey = priKey;
}

int ECDSA::generateSignature(const char* message, char* signature){
	//SIGNATURE GENERATION
	//1. hash the message
	unsigned char* digest = new unsigned char[256];
	
	SHA256 sha256 = SHA256();
	sha256.init();
	sha256.update((unsigned char*) message, strlen(message));
	sha256.final(digest);
	
	//convert digest to number
	mpz_t hashvalue;
	mpz_init(hashvalue);
	for (int i=31;i>=0;i--){
		mpz_mul_ui(hashvalue, hashvalue, 256);
		mpz_add_ui(hashvalue, hashvalue, digest[i]);
	}
	mpz_mod(hashvalue, hashvalue, this->curve->n); //truncate to have the same bit length as n
	
	//2. generate random number from 1 to n-1
	//2.1. seeding random generator
	int requested_security_strength = this->curve->getRequestSecurityLength();
	gmp_randstate_t randomstate;
	gmp_randinit_default(randomstate);		
	mpz_t seed;
	mpz_init(seed);
	utils::getRandomNumber(&seed, requested_security_strength/8);
	gmp_randseed(randomstate, seed);
	
	bool randomok = false;
	mpz_t k;
	mpz_t r;
	mpz_t s;
	mpz_init(r);

	do{
		//get random k			
		mpz_init(k);
		mpz_rrandomb(k, randomstate, requested_security_strength);
		mpz_mod(k, k, this->curve->n);
		
		//compute r		
		EC_point* p1 = this->curve->mul(this->curve->g, &k);
		mpz_mod(r,p1->x,this->curve->n);
		if (mpz_sgn(r)==0){
			continue;
		}					
		
		//compute s
		mpz_init_set(s, *(this->priKey));
		mpz_mul(s, s, r);
		mpz_add(s, s, hashvalue);			
		mpz_t invert_k;
		mpz_init(invert_k);
		mpz_invert(invert_k, k, this->curve->n);
		mpz_mul(s,s,invert_k);
		mpz_mod(s,s,this->curve->n);
		if (mpz_sgn(s)==0){
			continue;
		}
		randomok = true;
	}
	while (!randomok);	
	
	//output data
	char* outputData;
	char* xstr = mpz_get_str(NULL, 10, r);
	char* ystr = mpz_get_str(NULL, 10, s);
	int outputLength = strlen(xstr) + strlen(ystr)+1;
	outputData = new char[(outputLength/3+1)*4];
	
	strcpy(outputData, xstr);
	strcat(outputData, ";");
	strcat(outputData, ystr);
	
	//output signature is the base64 encoded of "x;y"
	char* outputDataBase64 = new char[outputLength*3];
	utils::Base64Encode((unsigned char*) outputData, outputLength, &outputDataBase64);
	strcpy(signature, outputDataBase64);
	return 0;
}

bool ECDSA::verifySignature(const char* message, const char* signature){
	
	char* twoPoints[2];
	utils::split((char*) signature, ';', twoPoints);
	
	mpz_t r;
	mpz_t s;
	mpz_init_set_str(r, twoPoints[0], 10);
	mpz_init_set_str(s, twoPoints[1], 10);		
	
	//precheck the curve and public key
	bool checkFail = false;
	if (!this->curve->contains(this->pubKey)) checkFail = true;
	EC_point* product = this->curve->mul(this->pubKey, &this->curve->n);			
	if (!product->inf) checkFail = true;
	
	if (checkFail){
		return false;
	}
	else{
		//verify
		bool checkSuccess=false;
		if (mpz_cmp(r, this->curve->n)>=0 || mpz_cmp(s, this->curve->n)>=0){
			checkSuccess=false;
		}
		else{	
			unsigned char* digest = new unsigned char[512];
			SHA256 sha256 = SHA256();			
			sha256.init();
			sha256.update((unsigned char*) message, strlen(message));
			sha256.final(digest);
						
			//convert digest to number
			mpz_t hashvalue;
			mpz_init_set_ui(hashvalue,0);
			for (int i=31;i>=0;i--){
				mpz_mul_ui(hashvalue, hashvalue, 256);
				mpz_add_ui(hashvalue, hashvalue, digest[i]);
			}			
			mpz_mod(hashvalue, hashvalue, this->curve->n); //truncate to have the same bit length as n			
			
			mpz_t w;
			mpz_init(w);
			mpz_invert(w, s, this->curve->n);
			
			mpz_t u1;
			mpz_init_set(u1, hashvalue);
			mpz_mul(u1, u1, w);
			mpz_mod(u1,u1,this->curve->n);
			
			mpz_t u2;
			mpz_init_set(u2, r);
			mpz_mul(u2, u2, w);
			mpz_mod(u2,u2,this->curve->n);
			
			EC_point* p2 = this->curve->mul(this->curve->g, &u1);
			EC_point* p3 = this->curve->mul(this->pubKey, &u2);
			EC_point* p4 = this->curve->add(p2, p3);			
								
			if (mpz_cmp(r,p4->x)==0){
				checkSuccess = true;				
			}
			else{
				checkSuccess = false;				
			}
		}
		return checkSuccess;
	}
}

ECDSA::~ECDSA()
{
}

