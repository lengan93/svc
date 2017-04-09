#ifndef __TOM_UTILS__
#define __TOM_UTILS__

	#include <cstdlib>
	
	#ifdef _WIN32
		#include <direct.h>
		#include <Windows.h>
		#define getcwd _getcwd
	#else
		#include <unistd.h>
	#endif

	namespace utils{

		enum SVCNetwork  : uint8_t{
			NETWORK_TYPE_IPv4,
			NETWORK_TYPE_SATURN
		};

		//-- ERROR DESCRIPTIONS
		const std::string ERR_PERM = "Error: SVC daemon failed to start. Cannot write config file.";
		const std::string ERR_NOCONFIG = "Error: SVC daemon failed to start. Config file not valid.";
		const std::string ERR_NOIMAGE = "Error: SVC daemon failed to start. Image file not valid.";
		const std::string ERR_PARAM = "Error: bad syntax";
		const std::string ERR_RUNNING = "Error: SVC daemon is already running.";
		const std::string ERR_NOT_RUNNING = "Error: SVC daemon is not running.";
		const std::string ERR_BINDING_SOCKET = "Error: cannot bind socket";
		const std::string ERR_CONNECT_SOCKET = "Error: cannot connect to socket";
		const std::string ERR_NOT_SUPPORTED = "Error: not supported";
		const std::string ERR_NOT_CONNECTED = "Error: endpoint not connected";
		const std::string ERR_TIMEOUT = "Error: operation timed out";
		const std::string ERR_NO_MEMORY = "Error: no memory";
		const std::string ERR_NULL_POINTER = "Error: null pointer deferencing";
		const std::string ERR_DATA_DAMAGED = "Error: bad data format";
		const std::string ERR_INVALID_ADDRESS = "Error: invalid address";
		const std::string ERR_CONFLIT_ADDRESS = "Error: conflit in address space";

		#ifdef _WIN32
			const std::string pathSeparator = "\\";
		#else
			const std::string pathSeparator = "/";
		#endif

		static std::string tail(const std::string& source, size_t const length) {
			return (length >= source.size())? source : source.substr(source.size() - length);
		}

		static std::string getCurrentDirectory(bool separator){
			std::string result = std::string(getcwd(NULL,0));
			while (tail(result,1) == pathSeparator){
				result = result.substr(0, result.size()-1);
			}
			return separator? result + pathSeparator : result;
		}

		static std::string getOSTempDirectory(bool separator){
			#ifdef _WIN32
				char buffer[1024];
				GetTempPath(1024, buffer);
				std::string result = std::string(buffer);
			#else
				char* tmpDir = getenv("TMPDIR");
				std::string result = (tmpDir != NULL)? std::string(tmpDir) : std::string("/tmp");
			#endif
			while (tail(result,1) == pathSeparator){
				result = result.substr(0, result.size()-1);
			}
			return separator? result + pathSeparator : result;
		}
		
		static std::string hexToString(const uint8_t* data, uint32_t len){
			char buffer[len*2];
			memset(buffer, 0, len*2);
			uint8_t b;
			uint8_t c1=0;
			uint8_t c2=0;
			for (int i=0;i<len;i++){
				b = data[i];
				c1 = (b&0xF0)>>4;
				c2 = (b&0x0F);		
				buffer[2*i] = c1<10? (c1 + 48) : (c1 + 55);
				buffer[2*i+1] = c2<10? (c2 + 48) : (c2 + 55);
			}	
			return std::string(buffer, len*2);
		}

		static uint32_t stringToHex(const std::string& hexString, uint8_t* data){
			
			if (hexString.size()>0){		
				uint8_t c1;
				uint8_t c2;
				
				for (int i=0;i<hexString.size();i+=2){
					//-- extract first char
					c1 = hexString[i];
					if (c1>='A' && c1<='F')
						c1-= 55;
					else if (c1>='a' && c1<='f')
						c1-= 87;
					else
						c1-= 48;
					//-- extract second char
					c2 = hexString[i+1];
					if (c2>='A' && c2<='F')
						c2-= 55;
					else if (c2>='a' && c2<='f')
						c2-= 87;
					else
						c2-= 48;
					//-- calculate value
					data[i/2] = (uint8_t)(c1*16 + c2);
				}
				return hexString.size()/2;
			}
			else{
				return 0;
			}
		}

		static void printHexBuffer(const uint8_t* buffer, uint16_t bufferLen){
			for (int i=0; i<bufferLen; i++){
				printf("%0.2x ", buffer[i]);
			}
			printf("\n");
		}
	}
	
#endif
