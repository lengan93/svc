#include "ECCurve.h"

ECCurve::ECCurve(){
	mpz_init_set_str(this->p, w256_001_p, 10);
	mpz_init_set_str(this->n, w256_001_n, 10);
	mpz_init_set_str(this->a4, w256_001_a4, 10);
	mpz_init_set_str(this->a6, w256_001_a6, 10);		
	this->g = new ECPoint(w256_001_gx, w256_001_gy);
}

void ECCurve::add(ECPoint* rs, const ECPoint* P, const ECPoint* Q){	

	if (P->inf || Q->inf){		
		if (!P->inf){
			//return p1
			mpz_set(rs->x, P->x);
			mpz_set(rs->y, P->y);
		}
		else if (!Q->inf){
			mpz_set(rs->x, Q->x);
			mpz_set(rs->y, Q->y);
		}
		else{
			rs->inf = true;
		}
	}
	else if (mpz_cmp(P->x, Q->x)==0){
		if (mpz_cmp(P->y, Q->y)==0){
			//two identical points
			mpz_set(rs->x, P->x);
			mpz_set(rs->y, P->y);
			dbl(rs);
		}
		else{			
			rs->inf = true;			
		}
	}
	else{
		//compute the slope		
		mpz_t s;
		mpz_t denom;
		mpz_t xR;
		mpz_t yR;
		
		mpz_init_set(s, P->y);
		mpz_sub(s, s, Q->y);
	
		mpz_init_set(denom, P->x);			
		mpz_sub(denom, denom, Q->x);		
		mpz_invert(denom, denom, this->p);		
		mpz_mul(s, s, denom);
		mpz_mod(s, s, this->p);
		
		//compute R coordinate	

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
		
		//-- set result
		mpz_set(rs->x, xR);
		mpz_set(rs->y, yR);		
		
		mpz_clear(s);
		mpz_clear(denom);
		mpz_clear(xR);
		mpz_clear(yR);
	}	
}

void ECCurve::mul(ECPoint* rs, const ECPoint* P, const mpz_t* k){	
	if (mpz_sgn(*k)==0){
		rs->inf=true;		
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

		while (mpz_sgn(b_inverse)>0 || bitlength){
			bitlength--;		
			dbl(rs);
			if (mpz_odd_p(b_inverse)){
				add(rs, rs, P);
			}
			mpz_fdiv_q_ui(b_inverse, b_inverse, 2);
		}
		
		mpz_clear(b_inverse);
		mpz_clear(tmp);
	}
}

void ECCurve::dbl(ECPoint* rs){	
	
	if (rs->inf || mpz_sgn(rs->y)==0){
		rs->inf = true;
	}
	else{		
		//compute the slope
		mpz_t s;
		mpz_t denom;
		mpz_t xR;
		mpz_t yR;
		
		mpz_init(s);
		mpz_powm_ui(s, rs->x, 2, this->p);
		mpz_mul_ui(s, s, 3);
		mpz_add(s, s, this->a4);
		
		
		mpz_init_set(denom, rs->y);
		mpz_mul_ui(denom, denom, 2);
		mpz_invert(denom, denom, this->p);
		mpz_mul(s, s, denom);
		
		//compute xR and yR				
		//xR = s^2 - 2xP
		mpz_init(xR);
		mpz_powm_ui(xR, s, 2, this->p);
		mpz_sub(xR, xR, rs->x);
		mpz_sub(xR, xR, rs->x);
		mpz_mod(xR, xR, this->p);
		
		//yR = s(xP - xR) - yP
		mpz_init_set(yR, rs->x);
		mpz_sub(yR, yR, xR);
		mpz_mul(yR, yR, s);
		mpz_sub(yR, yR, rs->y);
		mpz_mod(yR, yR, this->p);
		
		mpz_set(rs->x, xR);
		mpz_set(rs->y, yR);
		
		mpz_clear(s);
		mpz_clear(denom);
		mpz_clear(xR);
		mpz_clear(yR);
	}
}

void ECCurve::opposite(ECPoint* rs, const ECPoint* P){
	mpz_t sum;
	mpz_init_set(sum, P->x);
	mpz_add(sum, sum, P->y);
	mpz_mod(sum, sum, this->p);
	
	mpz_set(rs->x, P->x);
	mpz_set(rs->y, sum);
	
	mpz_clear(sum);
}

bool ECCurve::contains(const ECPoint* p){
	if (p->inf){		
		return true;	
	}
	else{
		bool rs;
		mpz_t x3;
		mpz_t y2;
		mpz_t y;
		
		mpz_init(x3);
		mpz_powm_ui(x3, p->x, 3, this->p);
		mpz_init_set(y2, p->x);
		mpz_mul(y2,y2,this->a4);
		mpz_add(y2,y2,this->a6);
		mpz_add(y2,y2,x3);
		mpz_mod(y2,y2,this->p);
		
		mpz_init(y);
		mpz_powm_ui(y, p->y, 2, this->p);
		rs = (mpz_cmp(y,y2)==0);
		
		mpz_clear(x3);
		mpz_clear(y2);
		mpz_clear(y);
		return rs;
	}
}

int ECCurve::getRequestSecurityLength(){
	char* displayedN = mpz_get_str(NULL,2,this->n);
	int N = strlen(displayedN);
	free(displayedN);
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
	mpz_clear(this->a4);
	mpz_clear(this->a6);
	mpz_clear(this->n);
	mpz_clear(this->p);
	delete this->g;
}

