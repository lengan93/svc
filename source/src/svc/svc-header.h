/*		SVC-header contents common functionalities used by both SVC and SVC-daemon*/

#ifndef __SVC_HEADER__
#define __SVC_HEADER__
	
	#include <string>
		
	using namespace std;

	/*	HTP definitions */
	#define AF_HTP								AF_PHONET
	#define PF_HTP								PF_PHONET

	/*	SVC CONFIG	*/
	const uint16_t SVC_DEFAULT_BUFSIZ 		=		60000;
	
	const std::string SVC_PIPE_PREFIX = "svc-";
	const std::string SVC_ENDPOINT_PIPE_PREFIX = "svc-se";
	const std::string SVC_DAEMON_ENDPOINT_PIPE_PREFIX = "svc-de";
	const std::string SVC_DEFAULT_DAEMON_NAME = "daemon";
	
	/*	SVC CONSTANTS' LENGTHS	*/
	#define INFO_LENGTH					2
	#define ENDPOINTID_LENGTH			8
	#define SEQUENCE_LENGTH				4
	#define APPID_LENGTH				4
	#define SVC_PACKET_HEADER_LEN		INFO_LENGTH + ENDPOINTID_LENGTH + SEQUENCE_LENGTH
	
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

	#define SVC_SUCCESS							0x01
	#define SVC_FAILED							0x00

	/*	ABI, DO NOT MODIFY UNLESS YOU KNOW EXACTLY WHAT	YOU DO	*/
	enum SVCCommand : uint8_t{
		SVC_CMD_REGISTER_SVC,
		SVC_CMD_SHUTDOWN_SVC,
		SVC_CMD_CREATE_ENDPOINT,
		SVC_CMD_SHUTDOWN_ENDPOINT,
		//SVC_CMD_CHECK_ALIVE,
		//SVC_CMD_DAEMON_RESTART,
		SVC_CMD_CONNECT_INNER1,
		SVC_CMD_CONNECT_OUTER1,
		SVC_CMD_CONNECT_INNER2,
		SVC_CMD_CONNECT_INNER3,
		SVC_CMD_CONNECT_OUTER2,
		SVC_CMD_CONNECT_INNER4,
		SVC_CMD_CONNECT_INNER5,
		SVC_CMD_CONNECT_OUTER3,
		SVC_CMD_CONNECT_INNER6,
		SVC_CMD_CONNECT_INNER7,
		SVC_CMD_STOP_DAEMON,
		SVC_CMD_DAEMON_DOWN,
		_SVC_CMD_COUNT
	};
	/*	END OF ABI	*/
	
#endif
