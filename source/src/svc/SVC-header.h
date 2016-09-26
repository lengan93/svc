/*		SVC-header contents common functionalities used by both SVC and SVC-daemon*/

#ifndef __SVC_HEADER__
#define __SVC_HEADER__
	
	#include <linux/types.h>
	#include <string>	
		
	using namespace std;

	/*	HTP definitions */
	#define AF_HTP								AF_PHONET
	#define PF_HTP								PF_PHONET
	
	/*	SVC ERROR DESCRIPTION	*/
	#define SVC_ERROR_NAME_EXISTED				"Application is already running"
	#define SVC_ERROR_UNEXPECTED_RESPONSE		"Unexpected response"
	#define SVC_ERROR_NOT_ESTABLISHED			"Connection not established"
	#define SVC_ERROR_REQUEST_TIMEDOUT			"Request timed out"
	#define SVC_ERROR_AUTHENTICATION_FAILED		"Authentication failed"
	#define SVC_ERROR_CRITICAL					"Critical error"
	#define SVC_ERROR_BINDING					"Error binding socket"
	#define SVC_ERROR_NOTIFICATOR_DUPLICATED	"Notificator duplicated"	
	#define SVC_ERROR_SIGNAL_INTERRUPTED		"Execution interrupted by SIGINT"

	/*	SVC CONSTANTS	*/
	#define SVC_ACQUIRED_SIGNAL					SIGUSR1
	#define SVC_SHARED_MUTEX_SIGNAL				SIGUSR1
	#define SVC_PERIODIC_SIGNAL					SIGUSR2
	#define SVC_TIMEOUT_SIGNAL					SIGALRM
	#define SVC_PERIODIC_SIGNAL					SIGUSR2

	#define SVC_DEFAULT_TIMEOUT 				5000
	#define SVC_SHORT_TIMEOUT					5000
	#define SVC_DEFAULT_BUFSIZ 					65536
	#define	SVC_DAEPORT							1221
	#define SVC_ENDPOINT_LIVETIME				5000
		
	/*	SVC CONSTANTS' LENGTHS	*/
	#define 		APPID_LENGTH				4	
	#define 		ENDPOINTID_LENGTH			8
	static uint32_t	SESSIONID_LENGTH	=		4;

	/*	SVC INFO BIT	*/
	#define SVC_COMMAND_FRAME  					0x80
	#define SVC_DAEMON_RESPONSE					0x40
	#define SVC_ENCRYPTED						0x08
	#define SVC_USING_TCP						0x04
	
	#define SVC_URGENT_PRIORITY 				0x03
	#define	SVC_HIGH_PRIORITY					0x02
	#define SVC_NORMAL_PRIORITY					0x01
	#define SVC_LOW_PRIORITY					0x00

	static uint32_t SVC_DEFAULT_SESSIONID 	= 	0;	
	
	static std::string SVC_DAEMON_PATH = 			"/tmp/svc-daemon";
	static std::string SVC_CLIENT_PATH_PREFIX = 	"/tmp/svc-client-";
	
	
	/*	ABI, DO NOT MODIFY UNLESS YOU KNOW EXACTLY WHAT	YOU DO	*/
	enum SVCCommand : uint8_t{
		SVC_CMD_CHECK_ALIVE,
		SVC_CMD_CONNECT_INNER1,
		SVC_CMD_CONNECT_OUTER1,
		SVC_CMD_CONNECT_INNER2,
		SVC_CMD_CONNECT_INNER3,
		SVC_CMD_CONNECT_OUTER2,
		SVC_CMD_CONNECT_INNER4,
		SVC_CMD_CONNECT_INNER5,
		SVC_CMD_CONNECT_INNER6,
		SVC_CMD_CONNECT_INNER7,
		SVC_CMD_CONNECT_OUTER3,
		SVC_CMD_CONNECT_INNER8,
		SVC_CMD_CONNECT_INNER9,
		_SVC_CMD_COUNT
	};
	/*	END OF ABI	*/	
	
#endif
