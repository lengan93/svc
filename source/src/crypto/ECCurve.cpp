#include "EC_curve.h"

EC_curve::EC_curve(){
	
}

EC_curve::EC_curve(const char* p, const char* n, const char* a4, const char* a6, const EC_point* g)
{
	mpz_init_set_str(this->p, p, 10);
	mpz_init_set_str(this->n, n, 10);
	mpz_init_set_str(this->a4, a4, 10);
	mpz_init_set_str(this->a6, a6, 10);
	this->g = new EC_point(&g->x, &g->y);	
}

EC_point* EC_curve::add(const EC_point* P, const EC_point* Q){	
	EC_point* result;

	if (P->inf || Q->inf){		
		if (!P->inf){
			//return p1
			result = new EC_point(&P->x, &P->y);
		}
		else if (!Q->inf){
			result = new EC_point(&Q->x, &Q->y);			
		}
		else{
			result = new EC_point();
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
			result = new EC_point();
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
		
		result = new EC_point(&xR, &yR);
		return result;
	}	
}

EC_point* EC_curve::mul(const EC_point* P, const mpz_t* k){
	if (mpz_sgn(*k)==0){
		EC_point* result = new EC_point();
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

		EC_point* result = new EC_point();

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

EC_point* EC_curve::dbl(const EC_point* P){	
	
	EC_point* result;
	if (P->inf || mpz_sgn(P->y)==0){
		result = new EC_point();
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
		
		return new EC_point(&xR, &yR);
	}
}

EC_point* EC_curve::opposite(const EC_point* P){
	mpz_t sum;
	mpz_init_set(sum, P->x);
	mpz_add(sum, sum, P->y);
	mpz_mod(sum, sum, this->p);
	
	EC_point* result = new EC_point(&P->x, &sum);
}

bool EC_curve::contains(const EC_point* p){
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

int EC_curve::getRequestSecurityLength(){
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


EC_curve::~EC_curve(){
}

