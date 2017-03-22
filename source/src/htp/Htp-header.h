#ifndef __HTP_HEADER_H__
#define __HTP_HEADER_H__

#include <cstring>
#include <fstream>
#include <sys/socket.h>
#include <sys/types.h>
#include <list>
#include <set>
#include <mutex>
#include "../svc/svc-header.h"

#define SENT_BUFFER_MAX_SIZE 50

#define HTP_HEADER_LENGTH 1
// #define HTP_SEQUENCE_LENGTH 4

#define HTP_PACKET_MINLEN 14 //(1+1+ENDPOINTID_LENGTH+SEQUENCE_LENGTH)

#define HTP_DEFAULT_BUFSIZ 65556

// typedef uint8_t HtpFrame;

// HTP Info byte
#define HTP_DATA	0x80
#define HTP_ACK		0x40
#define HTP_NACK	0X20

#endif