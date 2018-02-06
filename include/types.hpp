#ifndef __TYPES_HPP
#define __TYPES_HPP

#include <time.h>
#include "openssm_error.h"
#include "sgx_tcrypto.h"

#define MAX_SERILIZED_KEY_SIZE 4*1024

#define OPENSSM_MK_SCHEME_TYPE(x)              	 (0x0000|(x))
#define OPENSSM_MK_SERVICE_REQUEST(x)            (0x7FFF & ( x )) //MSB is always zero
#define OPENSSM_MK_SERVICE_RESPONSE(x)           (0x8000 | ( x )) //MSB is always one

typedef enum : uint16_t
{
    KEY_SCHEME_NULL_ENCRYPTION  = OPENSSM_MK_SCHEME_TYPE(0x0000),
    AES_GCM_128_DOUBLE_NONCE    = OPENSSM_MK_SCHEME_TYPE(0x0001),
} SessionKeysScheme;


typedef enum : uint16_t
{
    NULL_ENCRYPTION         = OPENSSM_MK_SCHEME_TYPE(0x0000),
    AES_GCM_128       		= OPENSSM_MK_SCHEME_TYPE(0x0001),
    INVALID_SCHEME          = OPENSSM_MK_SCHEME_TYPE(0x00FF),
} SessionEncryptionScheme;


typedef struct 
{
    bool serviceIsAllowed;
    // size_t remainingInvocationsAllowed;
} ServiceInfo;

typedef OpenSSMStatus (*ServiceCallback)(void*, uint32_t, void*, size_t);   

typedef struct 
{
    uint16_t        numEntries;
    ServiceCallback *handlers;
    ServiceInfo     *servicesInfo;
} ServicesTable;

typedef enum : uint16_t
{
    PING                     = OPENSSM_MK_SERVICE_REQUEST ( 0x0000 ),
    RSA_GENERATE_KEY_PAIR    = OPENSSM_MK_SERVICE_REQUEST ( 0x0001 ),
    RSA_SIGN                 = OPENSSM_MK_SERVICE_REQUEST ( 0x0002 ),

    ECDSA_GENERATE_KEY_PAIR  = OPENSSM_MK_SERVICE_REQUEST ( 0x0003 ),
    ECDSA_SIGN               = OPENSSM_MK_SERVICE_REQUEST ( 0x0004 ),

    AES_GCM_GENERATE_KEY     = OPENSSM_MK_SERVICE_REQUEST ( 0x0005 ),
    AES_GCM_ENCRYPT          = OPENSSM_MK_SERVICE_REQUEST ( 0x0006 ),
    AES_GCM_DECRYPT          = OPENSSM_MK_SERVICE_REQUEST ( 0x0007 ),

    ALLOW_USER_REGISTRATION  = OPENSSM_MK_SERVICE_REQUEST ( 0x0008 ),
    PROVE_SSM_IDENTITY       = OPENSSM_MK_SERVICE_REQUEST ( 0x0009 ),

    ARM_KEY                  = OPENSSM_MK_SERVICE_REQUEST ( 0x000A ),
    GET_CHALLENGE            = OPENSSM_MK_SERVICE_REQUEST ( 0x000B ),
    IMPORT_RSA_KEY           = OPENSSM_MK_SERVICE_REQUEST ( 0x000C ),

    AES_CMAC                 = OPENSSM_MK_SERVICE_REQUEST ( 0x000D ),

    CREATE_ACCOUNT           = OPENSSM_MK_SERVICE_REQUEST ( 0x000E ),
    TRANSACTION              = OPENSSM_MK_SERVICE_REQUEST ( 0x000F ),

    GET_CONFIG_ID            = OPENSSM_MK_SERVICE_REQUEST ( 0x0010 ),

    ECDSA_GENERATE_KEY_PAIR_OPENSSL = OPENSSM_MK_SERVICE_REQUEST ( 0x0011 ),
    ECDSA_SIGN_OPENSSL              = OPENSSM_MK_SERVICE_REQUEST ( 0x0012 ),
    NUM_SERVICES,

    ERROR_MSG                        = 0xf000,
} SecureMsgType;

#define MK_RESPONSE(x) (SecureMsgType)(OPENSSM_MK_SERVICE_RESPONSE(x))

union AES_GCM_IV
{
    uint8_t asBytes[ SGX_AESGCM_IV_SIZE ];
    struct __attribute__((__packed__)) 
    {
        uint32_t constant;
        uint64_t counter;
    };
};

typedef struct __attribute__((__packed__)) 
{
    uint32_t data;
} PingMsg;

union SecureErrorMsg
{
    OpenSSMStatus errorCode;
    uint32_t      ENSURE_SIZE_FOUR_BYTES;
};

union KeyAttributes {
    uint64_t value;
    struct __attribute__((__packed__)) 
    {
        bool canBeUsedForSigning            : 1;
        bool canBeUSedForEncrypting         : 1;
        bool canBeUSedForDecrypting         : 1;
        bool storeOnDisk                    : 1;
        bool protecedKey                    : 1;
        bool canBeUSedForMAC                : 1;


        // bool canBeExportedAsClearText       : 1;
        // bool addExternalEntropyWhenCreating : 1;
        // bool canBeUSedForVerifying          : 1;
    };
};

#define KEY_PROTECTION_PASSWORD_SIZE    16
#define NONCE_SIZE                      16

typedef uint8_t ProtectionSecret[ KEY_PROTECTION_PASSWORD_SIZE ];
typedef uint8_t Nonce           [ NONCE_SIZE ] ;



typedef struct __attribute__((__packed__)) 
{
    KeyAttributes       attributes;
    time_t              creationTimestamp;      // Time of creation, provided by the remote client, 
                                                // as local time of the server cannot be trusted.
    uint16_t            modulusBits;
    uint16_t            publicExponentSize;
    uint8_t             publicExponent[];       // A buffer representing LibreSSL BigNum, created by using BN_bn2bin 
} RSAGenerateKeyPairMsg;

typedef struct __attribute__((__packed__)) 
{
    uint64_t handle;
    uint16_t publicKeySize;
    uint16_t certificateSize;
    uint8_t  publicKeyAndCertificate[];
} RSAGenerateKeyPairResponseMsg;

typedef struct __attribute__((__packed__)) 
{
    KeyAttributes       attributes;
} ECDSA_GenerateKeyPairMsg;


typedef struct __attribute__((__packed__)) 
{
    uint64_t handle;
    sgx_ec256_public_t publicKey;
} ECDSA_GenerateKeyPairResponseMsg;

typedef struct __attribute__((__packed__)) 
{
    KeyAttributes       attributes;
    
    uint16_t            curveNID;
} ECDSA_GenerateKeyPairOpenSSLMsg;

typedef struct __attribute__((__packed__)) 
{
    uint64_t handle;
    uint16_t publicKeySize;    
    uint8_t  publicKey[];
} ECDSA_GenerateKeyPairOpenSSLResponseMsg;

typedef struct __attribute__((__packed__)) 
{
    KeyAttributes       attributes;
    uint16_t            keySizeInBits;
} AES_GCM_GenerateKeyMsg;

typedef struct __attribute__((__packed__)) 
{
    uint64_t handle;
} AES_GCM_GenerateKeyResponseMsg;

typedef struct __attribute__((__packed__)) 
{
    AES_GCM_IV                  iv;
    sgx_aes_gcm_128bit_tag_t    tag;
    uint16_t                    cipherSize;
    uint8_t                     cipherText[];
} AES_GCM_EncryptResponseMsg;

typedef struct __attribute__((__packed__)) 
{
    AES_GCM_IV                  iv;
    sgx_aes_gcm_128bit_tag_t    tag;
    uint64_t                    keyHandle;
    uint16_t                    cipherSize;
    uint8_t                     cipherText[];
} AES_GCM_DecryptMsg;

typedef struct __attribute__((__packed__)) 
{
    sgx_cmac_128bit_tag_t ssmProofOfIdentity;
} ProveSSMIdentityResponse;

typedef struct __attribute__((__packed__)) 
{
    uint64_t keyHandle;
    uint16_t dataSize;
    uint8_t  data[];
} ProcessDataMsg;


typedef ProcessDataMsg RSASignMsg;
typedef ProcessDataMsg ECDSASignMsg;
typedef ProcessDataMsg ECDSASignOpenSSLMsg;
typedef ProcessDataMsg AES_GCM_EncryptMsg;
typedef ProcessDataMsg AES_CMAC_Msg;

typedef struct __attribute__((__packed__)) 
{
    uint16_t signatureSize;
    uint8_t  signature[];
} RSASignResponseMsg;

typedef struct __attribute__((__packed__)) 
{
    uint16_t signatureSize;
    uint8_t  signature[];
} ECDSAOpenSSL_SignResponseMsg;

typedef struct __attribute__((__packed__)) 
{
    uint16_t        privateKeySize;
    uint8_t         privateKeyAsDER[];
} ImportRSAKeyMsg;

typedef struct __attribute__((__packed__)) 
{
    uint64_t keyHandle;
} ImportRSAKeyResponse;

typedef struct __attribute__((__packed__)) 
{
    sgx_ec256_signature_t  signature;
} ECDSASignResponseMsg;

typedef struct __attribute__((__packed__)) 
{
    sgx_cmac_128bit_tag_t  mac;
} AES_CMAC_ResponseMsg;

typedef struct __attribute__((__packed__)) 
{
    sgx_cmac_128bit_tag_t  allowedUsersTAG;
} GET_CONFIG_ID_ResponseMsg;

typedef struct __attribute__((__packed__)) 
{
    uint16_t plainSize;
    uint8_t  plainText[];
} AES_GCM_DecryptResponseMsg;

typedef enum : uint64_t
{
   RSA_KEY                 = 0x1,
   ECDSA_KEY               = 0x2,
   AES_GCM_128_KEY         = 0x3,
   ECDSA_OPENSSL_KEY       = 0x4,

   AES_KEY_128             = 128,
   AES_KEY_192             = 192,
   AES_KEY_256             = 256,
} KeyObjectType;

typedef uint8_t AES_KEY[ 32 ];

typedef struct __attribute__((__packed__)) 
{
    uint64_t        type;
    KeyAttributes   attributes;
    uint64_t        handle;
    void*           object;
} KeyObject;

typedef struct __attribute__((__packed__)) 
{
    KeyObjectType               type;
    KeyAttributes               attributes;
    uint64_t                    handle;
    sgx_aes_gcm_128bit_tag_t    mac;
    uint8_t                     encryptedKeyMaterial[];
} SerializedKeyObject;



typedef struct __attribute__((__packed__)) 
{
    AES_KEY                   key;
    AES_GCM_IV                iv;
} AES_GCM_128_Context;

typedef struct __attribute__((__packed__)) 
{
    sgx_sha256_hash_t userID;
} UserID;

typedef bool AllowedServicesMap[ NUM_SERVICES ];

typedef struct __attribute__((__packed__)) 
{
    UserID userID;
    AllowedServicesMap allowedServicesMap;
} UserPermissions;

typedef UserPermissions AllowUserRegistrationMsg;

typedef struct __attribute__((__packed__)) 
{
    Nonce ssmNonce;
} GetChallengeResponse;
    
#define SECURE_MSG_BUFFER_SIZE 4096

union SecureMsg  
{
	uint8_t 				asBuffer[ SECURE_MSG_BUFFER_SIZE ];
	struct __attribute__((__packed__))  {
    	SecureMsgType        type;
    	uint8_t              body[];
	} ;
};

#define KEY_DERIVATION_CONTEXT_SIZE 32

//The following struct is used in key derivation process, as officially defined in NIST SP 800-108
//http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf
struct __attribute__((__packed__)) 
KeyDerivationData {
        uint8_t     counter;
        uint16_t    label;
        uint8_t     alwaysZero;
        uint8_t     context[ KEY_DERIVATION_CONTEXT_SIZE ];
        uint16_t    lengthOfDerivedKey;
};


typedef struct __attribute__((__packed__)) 
{
    UserID                          userID;
    Nonce                           userNonce;
    sgx_aes_gcm_128bit_tag_t        mac;
    ProtectionSecret                protectionSecret;
    // sgx_sha256_hash_t               keyRequestDigest;
} ProtectionToken;

typedef struct __attribute__((__packed__)) 
{
    uint16_t            numParticipants;
    ProtectionToken     protectionTokens[];
} SharedCustodySpec;

typedef struct __attribute__((__packed__)) 
{
    uint64_t            keyHandle;
    SharedCustodySpec   sharedCustodySpec;
} ArmKeyRequest;

typedef struct __attribute__((__packed__)) 
{
    double minimumAllowedBalance;
} CreateAccountRequest;

typedef struct __attribute__((__packed__)) 
{
    uint64_t accountHandle;
} CreateAccountResponse;

typedef struct __attribute__((__packed__)) 
{
    uint64_t accountHandle;
    double   transactionAmount;
} TransactionRequest;

typedef struct __attribute__((__packed__)) 
{
    double balanceAfterTransaction;
} TransactionResponse;

#define AES_GCM_128_DOUBLE_NONCE_PAYLOAD_SIZE 	( KEY_DERIVATION_CONTEXT_SIZE / 2 )

#endif
