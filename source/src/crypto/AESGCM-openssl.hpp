#ifndef _AES_GCM_SSL
#define _AES_GCM_SSL

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define KEY_LENGTH 256

class AESGCM_SSL
{
private:
	uint8_t key[KEY_LENGTH];
public:
	AESGCM_SSL(const uint8_t* key) {
		memcpy(this->key, key, KEY_LENGTH);
	}

	int encrypt(uint8_t *iv, int iv_len, uint8_t *plaintext, int plaintext_len, 
		uint8_t *aad,	int aad_len, /*unsigned char *key,*/ 
		uint8_t **ciphertext, uint32_t &ciphertext_len, uint8_t **tag)
	// int encrypt(const uint8_t* iv, const uint16_t iv_len, const uint8_t* plaintext, const uint32_t plaintext_len, 
	// 	const uint8_t* aad, const uint16_t aad_len, uint8_t** ciphertext, uint32_t* ciphertext_len, 
	// 	uint8_t* tag, uint16_t* tag_len)
	{
		EVP_CIPHER_CTX *ctx;

		int len;

		// int ciphertext_len;

		*ciphertext = (uint8_t*)malloc(plaintext_len);
		*tag = (uint8_t*)malloc(16);

		/* Create and initialise the context */		
		if(!(ctx = EVP_CIPHER_CTX_new())) throw "EVP_CIPHER_CTX_new";

		/* Initialise the encryption operation. */
		if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
			throw "EVP_EncryptInit_ex";
		/* Set IV length if default 12 bytes (96 bits) is not appropriate */
		if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
			throw "EVP_CIPHER_CTX_ctrl";

		/* Initialise key and IV */
		if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, this->key, iv))
			throw "EVP_EncryptInit_ex2";

		/* Provide any AAD data. This can be called zero or more times as
		 * required
		 */
		if(aad != NULL && aad_len!=0) {
			if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
				throw "EVP_EncryptUpdate";
		}
		/* Provide the message to be encrypted, and obtain the encrypted output.
		 * EVP_EncryptUpdate can be called multiple times if necessary
		 */
		if(1 != EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len))
			throw "EVP_EncryptUpdate2";
		ciphertext_len = len;

		/* Finalise the encryption. Normally ciphertext bytes may be written at
		 * this stage, but this does not occur in GCM mode
		 */
		if(1 != EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len)) 
			throw "EVP_EncryptFinal_ex";
		(ciphertext_len) += len;

		/* Get the tag */
		if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, *tag))
			throw "EVP_CIPHER_CTX_ctrl2";
		
		/* Clean up */
		EVP_CIPHER_CTX_free(ctx);

		return ciphertext_len;
	}

	// int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
 //    int aad_len, unsigned char *tag, /*unsigned char *key,*/ unsigned char *iv,
 //    unsigned char *plaintext)
    int decrypt(uint8_t *iv, int iv_len, uint8_t *ciphertext, int ciphertext_len, 
		uint8_t *aad,	int aad_len, /*unsigned char *key,*/ 
		uint8_t *tag, uint8_t **plaintext, uint32_t &plaintext_len)
	{
	    EVP_CIPHER_CTX *ctx;
	    int len;
	    // int plaintext_len;
	    int ret;

	    *plaintext = (uint8_t*)malloc(ciphertext_len);
		// *tag = (uint8_t*)malloc(16);

	    /* Create and initialise the context */
	    if(!(ctx = EVP_CIPHER_CTX_new())) throw "EVP_CIPHER_CTX_new";

	    /* Initialise the decryption operation. */
	    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
	        throw "EVP_DecryptInit_ex";

	    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
	    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
	        throw "EVP_CIPHER_CTX_ctrl";

	    /* Initialise key and IV */
	    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) throw "EVP_DecryptInit_ex2";

	    /* Provide any AAD data. This can be called zero or more times as
	     * required
	     */
		if(aad != NULL && aad_len!=0) {
	    	if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
	        throw "EVP_DecryptUpdate";
		}

	    /* Provide the message to be decrypted, and obtain the plaintext output.
	     * EVP_DecryptUpdate can be called multiple times if necessary
	     */
	    if(!EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len))
	        throw "EVP_DecryptUpdate2";
	    plaintext_len = len;

	    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
	        throw "EVP_CIPHER_CTX_ctrl2";

	    /* Finalise the decryption. A positive return value indicates success,
	     * anything else is a failure - the plaintext is not trustworthy.
	     */
	    ret = EVP_DecryptFinal_ex(ctx, *plaintext + len, &len);

	    /* Clean up */
	    EVP_CIPHER_CTX_free(ctx);

	    if(ret > 0)
	    {
	        /* Success */
	        plaintext_len += len;
	        // cout << "decrypt success, return " << plaintext_len <<endl;
	        return plaintext_len;
	    }
	    else
	    {
	        /* Verify failed */
	        cout << "decrypt failed" <<endl;
	        return -1;
	    }
	}

	void handleErrors() {
		// ERR_print_errors_fp (stderr);
		throw "ERROR!!";
	}

	~AESGCM_SSL();
	
};

#endif