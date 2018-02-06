#ifndef __OPENSSM_ERROR_H
#define __OPENSSM_ERROR_H



#define OPENSSM_MK_ERROR(x)              (0x00000000|(x))

typedef enum 
{
    OPENSSM_SUCCESS            			                    = OPENSSM_MK_ERROR(0x0000),
    OPENSSM_UNEXPECTED         			                    = OPENSSM_MK_ERROR(0x0001),      /* Unexpected error */
    OPENSSM_ENCLAVE_INIT_FAILED                             = OPENSSM_MK_ERROR(0x0002),      /* Failed initializing enclave*/
    OPENSSM_ENCLAVE_DESTROY_FAILED                          = OPENSSM_MK_ERROR(0x0003),      /* Failed destroying enclave*/
    OPENSSM_GET_EPID_FAILED      		                    = OPENSSM_MK_ERROR(0x0004),      /* Failed calling sgx_get_extended_epid_group_id*/
    OPENSSM_GET_EPID_RETURNED_NONZERO 	                    = OPENSSM_MK_ERROR(0x0005),      /* sgx_get_extended_epid_group_id returned group ID != 0*/
    OPENSSM_INIT_RA_FAILED      		                    = OPENSSM_MK_ERROR(0x0006),      /* Failed calling sgx_init_ra inside enclave */
    OPENSSM_INIT_RA_FAILED_BAD_STATE	                    = OPENSSM_MK_ERROR(0x0007),      /* Requesting init of attestation process, but SSM in state != WAITING_FOR_INIT */
    OPENSSM_INIT_GET_MSG1_FAILED   		                    = OPENSSM_MK_ERROR(0x0008),      /* sgx_ra_get_msg1 failed */
    OPENSSM_INIT_GET_MSG2_BAD_MSG  		                    = OPENSSM_MK_ERROR(0x0009),      /* Error parsing msg2 */
    OPENSSM_INIT_GET_MSG2_CALL_INIT_RA                      = OPENSSM_MK_ERROR(0x000A),      /* Requesting msg2 before msg1. I.e., state != WAITING_FOR_MSG2*/
    OPENSSM_INIT_GET_MSG2_FAILED		                    = OPENSSM_MK_ERROR(0x000B),      /* sgx_ra_proc_msg2 failed*/

    OPENSSM_ESTABLISH_SESSION_FAILED_BAD_STATE              = OPENSSM_MK_ERROR(0x000C),      /* Establishing session failed because SSM state != WAITING_FOR_SESSION_REQUEST*/
    OPENSSM_ESTABLISH_SESSION_FAILED_BAD_MSG                = OPENSSM_MK_ERROR(0x000D),      /* Establishing session failed message size is bad */
    OPENSSM_ESTABLISH_SESSION_FAILED_UNEXPECTED             = OPENSSM_MK_ERROR(0x000E),      /* Establishing session failed ecall failed */
    OPENSSM_ESTABLISH_SESSION_FAILED_BAD_SCHEME             = OPENSSM_MK_ERROR(0x000F),      /* Establishing session bad scheme */
    OPENSSM_ESTABLISH_SESSION_FAILED_SGX_ERROR              = OPENSSM_MK_ERROR(0x0010),      /* Establishing session bad scheme */

    OPENSSM_ENCRYPTED_MSG_FAILED_BAD_STATE                  = OPENSSM_MK_ERROR(0x0011),      /* Got encrypted message, but in bad state*/
    OPENSSM_ENCRYPTED_MSG_FAILED_BAD_MSG                    = OPENSSM_MK_ERROR(0x0012),      /* Handling encrypted msg failed: message size is bad */
    OPENSSM_ENCRYPTED_MSG_FAILED_BAD_SCHEME                 = OPENSSM_MK_ERROR(0x0013),      /* Handling encrypted msg failed: bad scheme */
    OPENSSM_ENCRYPTED_MSG_FAILED_BAD_MAC                    = OPENSSM_MK_ERROR(0x0014),      /* Handling encrypted msg failed: MAC is bad (decryption failed) */
    OPENSSM_ENCRYPTED_MSG_FAILED_UNEXPECTED                 = OPENSSM_MK_ERROR(0x0015),      /* Handling encrypted msg failed: MAC is bad (decryption failed) */
    OPENSSM_ENCRYPTED_MSG_FAILED_RESPONSE_BUFFER_TOO_SMALL  = OPENSSM_MK_ERROR(0x0016),      /* Handling encrypted msg failed: provided response buffer is too small*/

    OPENSSM_BAD_MSG_HEADER 				                    = OPENSSM_MK_ERROR(0x0100),      /* Bad OpenSSMMsgHeader, totalLength is probaly too big */
    OPENSSM_UNKNOWN_MESSAGE_TYPE                            = OPENSSM_MK_ERROR(0x0101),      /* Bad OpenSSMMsgHeader, totalLength is probaly too big */
    OPENSSM_BAD_PARAMETER                                   = OPENSSM_MK_ERROR(0x0102),      /* Bad parameter given to function */
    OPENSSM_CANT_SEAL_MASTER_SECRETS                        = OPENSSM_MK_ERROR(0x0103),      /* Error while trying to seal master secrets */
    OPENSSM_BUFFER_TOO_SMALL                                = OPENSSM_MK_ERROR(0x0104),      /* Given buffer is not big enough to contain output */
    OPENSSM_ERROR_READING_SEALED_MASTER_KEYS                = OPENSSM_MK_ERROR(0x0105),      /* Can't read sealed keys from file */
    OPENSSM_CANT_UNSEAL_MASTER_SECRETS                      = OPENSSM_MK_ERROR(0x0106),      /* Error while trying to unseal master secrets */

    OPENSSM_SECURE_MSG_BAD_SIZE                             = OPENSSM_MK_ERROR(0x0107),      /* Bad size arguments inside secure message */
    OPENSSM_SECURE_MSG_SIGNING_NOT_ALLOWED_IN_ATTRIBUTES    = OPENSSM_MK_ERROR(0x0108),      /* Attributes of object don't allow signing */
    OPENSSM_SECURE_MSG_UNEXPECTED_ERROR                     = OPENSSM_MK_ERROR(0x0109),      /* Unexpected error */
    OPENSSM_SECURE_MSG_BAD_HANDLE                           = OPENSSM_MK_ERROR(0x010A),      /* Invalid handle */
    OPENSSM_SECURE_MSG_BAD_KEY_SIZE                         = OPENSSM_MK_ERROR(0x010B),      /* Unsupported key size */
    OPENSSM_SECURE_MSG_OPERATION_NOT_ALLOWED_IN_ATTRIBUTES  = OPENSSM_MK_ERROR(0x010C),      /* Attributes of object don't allow the requested operation */
    OPENSSM_SECURE_MSG_MAC_MISMATCH                         = OPENSSM_MK_ERROR(0x010D),      /* MAC verification failed */
    OPENSSM_SECURE_MSG_UNKNOWN_MSG                          = OPENSSM_MK_ERROR(0x010E),      /* Unknown secure message type */
    OPENSSM_SECURE_MSG_SHARED_CUSTUDY_ERROR                 = OPENSSM_MK_ERROR(0x010F),      /* Failed parsing SharedCustodySpec */
    OPENSSM_SECURE_FAILED_READING_KEY_FROM_FILE             = OPENSSM_MK_ERROR(0x0110),      /* Error reading key from file */
    OPENSSM_SECURE_FAILED_UNSEALING_KEY_FROM_FILE           = OPENSSM_MK_ERROR(0x0111),      /* Can't unseal key from file*/
    OPENSSM_SECURE_MSG_BAD_KEY_ENCODING                     = OPENSSM_MK_ERROR(0x0112),      /* Can't decode DER key*/
} OpenSSMStatus;

#endif