#ifndef __HTP_HEADER_H__
#define __HTP_HEADER_H__

#include <cstring>
#include <fstream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <list>
#include <set>
#include <unordered_set>
#include <mutex>
#include "../svc/svc-header.h"
#include "../utils/timer.h"

#define SENT_WINDOW_MAX_SIZE 50

#define HTP_HEADER_LENGTH 11 // 1 byte flag + 4 bytes sessionID + 4 bytes sequence + 2 bytes streamID
#define HTP_SESSIONID_LENGTH 4
#define HTP_SEQUENCE_LENGTH 4
#define HTP_STREAMID_LENGTH 2

#define HTP_PACKET_MINLEN 9 //(1+HTP_SESSIONID_LENGTH+HTP_SEQUENCE_LENGTH)

#define HTP_DEFAULT_BUFSIZ 65556

// typedef uint8_t HtpFrame;

// HTP Info byte
#define HTP_DATA		0x80
#define HTP_ACK			0x40
#define HTP_IMPT		0x20
#define HTP_STREAMED	0x10
#define HTP_START_SS	0x08
#define HTP_NACK		0x00

// #define HTP_PREV_DATA	0x08
// #define HTP_PREV_ACK	0x04
// #define HTP_PREV_IMPT	0x02
// #define HTP_PREV_SEQ	0x01

#define HTP_SEND_TIMEOUT 1000 //in ms

#endif