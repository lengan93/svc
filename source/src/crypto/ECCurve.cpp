#include "ECCurve.h"

ECCurve::ECCurve(){
	mpz_init_set_str(this->p, w256_001_p, 10);
	mpz_init_set_str(this->n, w256_001_n, 10);
	mpz_init_set_str(this->a4, w256_001_a4, 10);
	mpz_init_set_str(this->a6, w256_001_a6, 10);		
	this->g = new ECPoint(w256_001_gx, w256_001_gy);
}

ECPoint* ECCurve::add(const ECPoint* P, const ECPoint* Q){	
	ECPoint* result;

	if (P->inf || Q->inf){		
		if (!P->inf){
			//return p1
			result = new ECPoint(&P->x, &P->y);
		}
		else if (!Q->inf){
			result = new ECPoint(&Q->x, &Q->y);			
		}
		else{
			result = new ECPoint();
			result->inf = true;
		}		
		return result;
	}
	else if (mpz_cmp(P->x, Q->x)==0){
		if (mpz_cmp(P->y, Q->y)==0){
			//two identical points
			return dbl(P);
		}
		else{
			result = new ECPoint();
			result->inf = true;
			return result;
		}
	}
	else{
		//compute the slope		
		mpz_t s;
		mpz_t denom;
		
		mpz_init_set(s, P->y);
		mpz_sub(s, s, Q->y);
	
		mpz_init_set(denom, P->x);			
		mpz_sub(denom, denom, Q->x);		
		mpz_invert(denom, denom, this->p);		
		mpz_mul(s, s, denom);
		mpz_mod(s, s, this->p);
		
		//compute R coordinate
		mpz_t xR;
		mpz_t yR;

		//xR = s^2 - (xP + xQ)
		mpz_init(xR);
		mpz_powm_ui(xR, s, 2, this->p);
		mpz_sub(xR, xR, P->x);
		mpz_sub(xR, xR, Q->x);
		mpz_mod(xR, xR, this->p);
		
		//yR = s(xP - xR) - yP
		mpz_init_set(yR, P->x);
		mpz_sub(yR, yR, xR);
		mpz_mul(yR, yR, s);
		mpz_sub(yR, yR, P->y);
		mpz_mod(yR, yR, this->p);
		
		result = new ECPoint(&xR, &yR);
		return result;
	}	
}

ECPoint* ECCurve::mul(const ECPoint* P, const mpz_t* k){
	if (mpz_sgn(*k)==0){
		ECPoint* result = new ECPoint();
		result->inf=true;
		return result;
	}
	else
	{
		//compute inverse binary
		mpz_t b_inverse;
		mpz_t tmp;
		
		mpz_init(b_inverse);	
		mpz_init_set(tmp, *k);

		int bitlength=0;
		while (mpz_sgn(tmp)>0){
			bitlength++;
			mpz_mul_ui(b_inverse, b_inverse, 2);
			if (mpz_odd_p(tmp)){
				mpz_add_ui(b_inverse, b_inverse, 1);
			}
			mpz_fdiv_q_ui(tmp, tmp, 2);
		}

		ECPoint* result = new ECPoint();

		while (mpz_sgn(b_inverse)>0 || bitlength){
			bitlength--;		
			result = dbl(result);
			if (mpz_odd_p(b_inverse)){
				result = add(result, P);
			}
			mpz_fdiv_q_ui(b_inverse, b_inverse, 2);
		}
		return result;
	}
}

ECPoint* ECCurve::dbl(const ECPoint* P){	
	
	ECPoint* result;
	if (P->inf || mpz_sgn(P->y)==0){
		result = new ECPoint();
		result->inf = true;
		return result;
	}
	else{		
		//compute the slope
		mpz_t s;
		mpz_init(s);
		mpz_powm_ui(s, P->x, 2, this->p);
		mpz_mul_ui(s, s, 3);
		mpz_add(s, s, this->a4);
		
		mpz_t denom;
		mpz_init_set(denom, P->y);
		mpz_mul_ui(denom, denom, 2);
		mpz_invert(denom, denom, this->p);
		mpz_mul(s, s, denom);
		
		//compute xR and yR
		mpz_t xR;
		mpz_t yR;
		
		//xR = s^2 - 2xP
		mpz_init(xR);
		mpz_powm_ui(xR, s, 2, this->p);
		mpz_sub(xR, xR, P->x);
		mpz_sub(xR, xR, P->x);
		mpz_mod(xR, xR, this->p);
		
		//yR = s(xP - xR) - yP
		mpz_init_set(yR, P->x);
		mpz_sub(yR, yR, xR);
		mpz_mul(yR, yR, s);
		mpz_sub(yR, yR, P->y);
		mpz_mod(yR, yR, this->p);
		
		return new ECPoint(&xR, &yR);
	}
}

ECPoint* ECCurve::opposite(const ECPoint* P){
	mpz_t sum;
	mpz_init_set(sum, P->x);
	mpz_add(sum, sum, P->y);
	mpz_mod(sum, sum, this->p);
	
	return new ECPoint(&P->x, &sum);
}

bool ECCurve::contains(const ECPoint* p){
	if (p->inf){		
		return true;	
	}
	else{
		mpz_t x3;
		mpz_t y2;
		
		mpz_init(x3);
		mpz_powm_ui(x3, p->x, 3, this->p);
		mpz_init_set(y2, p->x);
		mpz_mul(y2,y2,this->a4);
		mpz_add(y2,y2,this->a6);
		mpz_add(y2,y2,x3);
		mpz_mod(y2,y2,this->p);
		
		mpz_t y;
		mpz_init(y);
		mpz_powm_ui(y, p->y, 2, this->p);
		return (mpz_cmp(y,y2)==0);
	}
}

int ECCurve::getRequestSecurityLength(){
	int N = strlen(mpz_get_str(NULL,2,this->n));
	if (N>=512){
		return 256;			
	}
	else if (N>=384){
		return 192;
	}
	else if (N>=256){
		return 128;
	}
	else if (N>=224){
		return 112;
	}
	else if (N>=160){
		return 80;
	}
	else{
		return -1;
	}
}


ECCurve::~ECCurve(){
	delete this->g;
}

