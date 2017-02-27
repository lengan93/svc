#ifndef __HTP_HEADER_H__
#define __HTP_HEADER_H__

#include <cstring>
#include <sys/socket.h>
#include <sys/types.h>

#define SENT_BUFFER_MAX_SIZE 20

#define HTP_HEADER_LENGTH 5
#define HTP_SEQUENCE_LENGTH 4

#define HTP_DEFAULT_BUFSIZ 65556

// typedef uint8_t HtpFrame;

// HTP Info byte
#define HTP_DATA	0x00
#define HTP_ACK		0x01
#define HTP_NACK	0X02

#endif