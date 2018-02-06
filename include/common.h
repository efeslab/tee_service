#ifndef __COMMON_H
#define __COMMON_H




#include "sgx_tcrypto.h"

#define SERVER_VERSION_LENGTH      16
#define ENCLAVE_VERSION_LENGTH     16

typedef struct __attribute__((__packed__)) 
{
	uint16_t					encryptionScheme;  //See SessionEncryptionScheme
	uint64_t 					msgNumber;   //The IV is derived from this value. AES-GCM is EXTREMELY SENSITIVE to repeated IVs.
											 //Therefore, this number should be used for debugging purposes only. The counter should be 
											 //independently maintained by both parties, to avoid same-IV attacks
	uint32_t 					userID;	
	sgx_aes_gcm_128bit_tag_t 	mac;	
	uint16_t					cipherSize;
	uint8_t	 					ciphertext[];
} EncryptedMsg;

#endif