/*		SVC-header contents common functionalities used by both SVC and SVC-daemon*/

#ifndef __SVC_HEADER__
#define __SVC_HEADER__
	
	#include <string>
		
	using namespace std;

	/*	HTP definitions */
	#define AF_HTP								AF_PHONET
	#define PF_HTP								PF_PHONET
	
	/*	SVC ERROR DESCRIPTION	*/
	// #define SVC_ERROR_NAME_EXISTED				"Application is already running"
	// #define SVC_ERROR_UNEXPECTED_RESPONSE		"Unexpected response"
	// #define SVC_ERROR_NOT_ESTABLISHED			"Connection not established"
	// #define SVC_ERROR_REQUEST_TIMEDOUT			"Request timed out"
	// #define SVC_ERROR_AUTHENTICATION_FAILED		"Authentication failed"
	// #define SVC_ERROR_CRITICAL					"Critical error"
	// #define SVC_ERROR_BINDING					"Error binding socket"
	// #define SVC_ERROR_CONNECTING				"Error connecting socket"	
	// #define SVC_ERROR_SIGNAL_INTERRUPTED		"Execution interrupted by SIGINT"
	const std::string ERR_PERM = "Error: svc daemon failed to start. Cannot write config file.";
	const std::string ERR_NOCONFIG = "Error: svc daemon failed to start. Config file not valid.";
	const std::string ERR_NOIMAGE = "Error: svc daemon failed to start. Image file not valid.";
	const std::string ERR_PARAM = "Error: bad syntax";
	const std::string ERR_RUNNING = "Error: svc daemon is already running.";
	const std::string ERR_NOT_RUNNING = "Error: svc daemon is not running.";
	const std::string ERR_BINDING_SOCKET = "Error: cannot bind socket";
	const std::string ERR_CONNECT_SOCKET = "Error: cannot connect to socket";
	const std::string ERR_NOT_SUPPORTED = "Error: not supported";
	const std::string ERR_NOT_CONNECTED = "Error: endpoint not connected";
	const std::string ERR_TIMEOUT = "Error: operation timed out";

	/*	SVC CONFIG	*/
	#define SVC_DEFAULT_TIMEOUT 				3000
	#define SVC_DEFAULT_BUFSIZ 					65536
	#define	SVC_DAEPORT							1221
	#define SVC_ENDPOINT_BEAT_LIVETIME			5
	#define SVC_ENDPOINT_INIT_LIVETIME			2000
	
	const std::string SVC_DEFAULT_DAEMON_NAME = "svcdaemon";
		
	/*	SVC CONSTANTS' LENGTHS	*/	
	#define HOST_ADDR_LENGTH			4
	#define APPID_LENGTH				4
	#define SEQUENCE_LENGTH				4
	#define ENDPOINTID_LENGTH			8
	#define SVC_PACKET_HEADER_LEN		13 //-- SVC_PACKET_HEADER_LEN = 1 (info byte) + ENDPOINTID_LENGTH + SEQUENCE_LENGTH
	#define	INFO_BYTE					0
	#define	CMD_BYTE					SVC_PACKET_HEADER_LEN
	
	/*	SVC INFO BIT	*/
	#define SVC_COMMAND_FRAME  					0x80
	#define SVC_NOLOST							0x40
	#define SVC_SEQUENCE						0x20
	//#define SVC_								0x10
	#define SVC_ENCRYPTED						0x08
	//#define SVC_								0x04
	
	#define SVC_URGENT_PRIORITY 				0x03
	#define	SVC_HIGH_PRIORITY					0x02
	#define SVC_NORMAL_PRIORITY					0x01
	#define SVC_LOW_PRIORITY					0x00
	


	/*	ABI, DO NOT MODIFY UNLESS YOU KNOW EXACTLY WHAT	YOU DO	*/
	enum SVCCommand : uint8_t{
		SVC_CMD_REGISTER,
		SVC_CMD_CREATE_ENDPOINT,
		SVC_CMD_SHUTDOWN_ENDPOINT,
		SVC_CMD_CHECK_ALIVE,
		SVC_CMD_DAEMON_RESTART,
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
		SVC_CMD_STOP_DAEMON,
		_SVC_CMD_COUNT
	};
	/*	END OF ABI	*/
	
#endif
