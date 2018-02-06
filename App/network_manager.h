#ifndef __NETWORK_MANAGER_H
#define __NETWORK_MANAGER_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

#include "../include/openssm_error.h"
#include "../Enclave/openssm_enclave.h"
#include "../include/common.h"
#include "../include/types.hpp"
#include "logger.h"

#include "sgx_tcrypto.h"


#define MSG_BUFFER_SIZE 4096
#define OPENSSM_MK_MSG_TYPE(x)              	(0x00000000|(x))

typedef enum : uint16_t
{
    REQUEST_GET_VERSION            		= OPENSSM_MK_MSG_TYPE(0x0001),
    RESPONSE_GET_VERSION         		= OPENSSM_MK_MSG_TYPE(0x0002),
    REQUEST_INIT_START         			= OPENSSM_MK_MSG_TYPE(0x0003),
    RESPONSE_INIT_MSG1         			= OPENSSM_MK_MSG_TYPE(0x0004),    
    REQUEST_INIT_MSG2         			= OPENSSM_MK_MSG_TYPE(0x0005),
    RESPONSE_INIT_MSG3         			= OPENSSM_MK_MSG_TYPE(0x0006),
    REQUEST_ESTABLISH_SESSION  			= OPENSSM_MK_MSG_TYPE(0x0007),
    RESPONSE_ESTABLISH_SESSION 			= OPENSSM_MK_MSG_TYPE(0x0008),
    REQUEST_ENCRYPTED_MSG  				= OPENSSM_MK_MSG_TYPE(0x0009),
    RESPONSE_ENCRYPTED_MSG 				= OPENSSM_MK_MSG_TYPE(0x000A),
    REQUEST_REGISTER_NEW_USER  			= OPENSSM_MK_MSG_TYPE(0x000B),
    RESPONSE_REGISTER_NEW_USER_MSG1 	= OPENSSM_MK_MSG_TYPE(0x000C),
    REQUEST_REGISTER_NEW_USER_MSG2		= OPENSSM_MK_MSG_TYPE(0x000D),
    RESPONSE_REGISTER_NEW_USER_MSG3 	= OPENSSM_MK_MSG_TYPE(0x000E),
    
    REQUEST_RESET 						= OPENSSM_MK_MSG_TYPE(0x0100),
    RESPONSE_RESET 						= OPENSSM_MK_MSG_TYPE(0x0101),
    REQUEST_SYNC 						= OPENSSM_MK_MSG_TYPE(0x0102),
    RESPONSE_SYNC 						= OPENSSM_MK_MSG_TYPE(0x0103),

    RESPONSE_ERROR         				= OPENSSM_MK_MSG_TYPE(0xf001)
} OpenSSMMsgType;


typedef struct 
{
	uint16_t		totalLength;
	OpenSSMMsgType 	msgType;

} OpenSSMMsgHeader;

union OpenSSMMsg 
{
	uint8_t 				asBuffer[ MSG_BUFFER_SIZE ];
	struct __attribute__((__packed__))  {
		OpenSSMMsgHeader 		header;
		uint8_t 				body[];
	};
};

typedef struct __attribute__((__packed__)) 
{
	char serverVersion [ SERVER_VERSION_LENGTH ];
	char enclaveVersion[ ENCLAVE_VERSION_LENGTH ];
} VersionMsg;

typedef struct __attribute__((__packed__)) 
{
	OpenSSMStatus errorCode;
	uint8_t		  extraInfo[]; 	  
} ErrorMsg;

typedef struct __attribute__((__packed__)) 
{
	UserID 				userID;
	SessionKeysScheme 	scheme;
	uint8_t	 			extraData[];
} EstablishSessionKeysMsg;

typedef struct __attribute__((__packed__)) 
{
	uint8_t	 				data[];
} EstablishSessionKeysResponse;

typedef struct __attribute__((__packed__)) 
{
	uint64_t lastSessionMsgCounter;
} SyncResponse;

class NetworkManager
{
public:
	NetworkManager();
	virtual ~NetworkManager();

	void Start( int port );
	bool IsMsgPending();

	virtual OpenSSMStatus GetNextMessage( OpenSSMMsg &msg );
	virtual OpenSSMStatus SendMessage   ( OpenSSMMsg &msg );

	virtual void CloseConnectionAndWaitForNextOne();

private:
    struct sockaddr_in mClientAddress;
    socklen_t 		   mClientAddressSize;
    int 			   mListenfd;
    int 			   mClientSocketfd;
    Logger  		   mLogger;

    void GetBytesFromSocket 		( void* buff, size_t numBytesToRead );
	void InitSocket 				( int port );
	void AcceptIncommingConnection 	();
	void ReportErrorAndExit 		(const char *msg);

};

#endif