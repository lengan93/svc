#ifndef __TOM_CRYPTO_UTILS__
#define __TOM_CRYPTO_UTILS__

	#include "../utils/utils-functions.h"
	#include <fcntl.h>    /* For O_RDWR */
	#include <unistd.h>   /* For open(), creat() */

	extern std::string hexToString(uint8_t* data, size_t len);
	extern int stringToHex(const std::string& hexString, uint8_t* data);
	extern void generateRandomData(uint32_t length, uint8_t* data);
	
#endif // UTILS_H
