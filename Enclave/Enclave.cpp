/*
 * Copyright (C) 2011-2016 Intel Corporation. All rights resertord.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
// #define PRINT_STATUS

#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <string.h>

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */

#include "openssm_enclave.h"
#include "sgx_tkey_exchange.h"
#include "sgx_trts.h"
#include "sgx_tseal.h" 

#include "../include/types.hpp"

typedef uint64_t FILE;  // openssl header files assume stdlib.h which contains FILE

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>


sgx_spinlock_t  encryptionSpinlock = SGX_SPINLOCK_INITIALIZER;
sgx_spinlock_t  decryptionSpinlock = SGX_SPINLOCK_INITIALIZER;
sgx_spinlock_t  printSpinlock       = SGX_SPINLOCK_INITIALIZER;

// using std;

//The following is copied from sdk/tseal/tSeal_internal.h
 /* set MISCMASK.exinfo_bit = 0 for data migration to the enclave 
   built with the SDK that supports exinfo bit */
#define SGX_MISCSEL_EXINFO     0x00000001  /* report #PF and #GP inside enclave */
#define TSEAL_DEFAULT_MISCMASK (~SGX_MISCSEL_EXINFO)



// This is the public EC key of the SP. The corresponding private EC key is
// used by the SP to sign data used in the remote attestation SIGMA protocol
// to sign channel binding data in MSG2. A successful verification of the
// signature confirms the identity of the SP to the ISV app in remote
// attestation secure channel binding. The public EC key should be hardcoded in
// the enclave or delivered in a trustworthy manner. The use of a spoofed public
// EC key in the remote attestation with secure channel binding session may lead
// to a security compromise. Every different SP the enlcave communicates to
// must have a unique SP public key. Delivery of the SP public key is
// determined by the ISV. The TKE SIGMA protocl expects an Elliptical Curve key
// based on NIST P-256
static const sgx_ec256_public_t SERVICE_PROVIDER_PUBLIC_KEY = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }
};

#include <map>
#include <vector>
using namespace std;

const AllowedServicesMap ADMINISTRATOR_ALLOWED_SERVICES[] = {
                                   true, // PING                     ,
                                   true, // RSA_GENERATE_KEY_PAIR    ,
                                   true, // RSA_SIGN                 ,
                                   true, // ECDSA_GENERATE_KEY_PAIR  ,
                                   true, // ECDSA_SIGN               ,
                                   true, // AES_GCM_GENERATE_KEY     ,
                                   true, // AES_GCM_ENCRYPT          ,
                                   true, // AES_GCM_DECRYPT          ,
                                   true, // ALLOW_USER_REGISTRATION  ,
                                   true, // PROVE_SSM_IDENTITY       ,
                                   true, // ARM_KEY                  ,
                                   true, // GET_CHALLENGE            ,
                                   true, // IMPORT_RSA_KEY           ,
                                   true, // AES_CMAC                 ,
                                   true, // CREATE_ACCOUNT           ,
                                   true, // TRANSACTION 
                                   true, // GET_CONFIG_ID
                                   true, //ECDSA_GENERATE_KEY_PAIR_OPENSSL_REQUEST
                                   true, //ECDSA_SIGN_OPENSSL_REQUEST
};

const uint16_t ADMINISTRATOR_NUM_ALLOWED_SERVICES = sizeof( ADMINISTRATOR_ALLOWED_SERVICES ) / sizeof( SecureMsgType );

typedef struct __attribute__((__packed__)) 
{
    UserID              userID;
    sgx_aes_gcm_128bit_key_t mk;
    sgx_aes_gcm_128bit_key_t sk;
} SharedKeys;

#define MAX_SSM_USERS 1000
#define OPENSSM_MK_ENUM(x)                  (0x00000000|(x))

typedef enum : uint32_t
{
    DECRYPTION_IV                 = OPENSSM_MK_ENUM(0x0001),
    ENCRYPTION_IV                 = OPENSSM_MK_ENUM(0x0002),
} AES_GCM_IVLabel;

typedef enum 
{
    IDLE                 = OPENSSM_MK_ENUM(0x0001),
    InProgress           = OPENSSM_MK_ENUM(0x0002),
    UserIDApproved       = OPENSSM_MK_ENUM(0x0003),
} RemoteAttestationState;


typedef struct __attribute__((__packed__)) 
{
    AES_GCM_IVLabel     label;
    uint64_t            msgCounter;
} AES_GCM_IVBuffer;


typedef struct __attribute__((__packed__)) 
{
    sgx_ec_key_128bit_t     sessionKey;
    AES_GCM_IVBuffer        decryptionIV;
    AES_GCM_IVBuffer        encryptionIV;
    SessionEncryptionScheme scheme;
} SessionContext;

void SetupServicesTable( ServicesTable &servicesTable );


class DrawerManager {
public:
    DrawerManager() {
        for( int i(0); i < NUM_WORKER_THREADS; i++ ){
            mDrawersAvailable[ i ] = true;
        }        
    }

    void* GetAvailableItem()
    {
        sgx_spin_lock( &lock );

        // printf("############# %s: %d; mDrawersAvailable = ", __FUNCTION__, __LINE__ );
        // for( int threadIdx = 0; threadIdx < NUM_WORKER_THREADS; threadIdx++ )
        //     printf("%d,", mDrawersAvailable[ threadIdx ] );

        for( int i(0); i < NUM_WORKER_THREADS; i++ ){
            if( mDrawersAvailable[ i ] == true ){
                mDrawersAvailable[ i ] = false;
                // printf("##########%s: %d; taking item %d; drawers[ i ] = %p\n", __FUNCTION__, __LINE__,i, drawers[ i ] );
                sgx_spin_unlock( &lock );
                return drawers[ i ];
            }
        }

        sgx_spin_unlock( &lock );
        printf("##########%s: %d; no more items available\n", __FUNCTION__, __LINE__  );
        return NULL;
    }

    void ReturnItem( void* item ){
        sgx_spin_lock( &lock );
        for( int i(0); i < NUM_WORKER_THREADS; i++ ){
            if( drawers[ i ] == item ){
                mDrawersAvailable[ i ] = true;
                // printf("##########%s: %d; Returning item %d\n", __FUNCTION__, __LINE__,i );
                sgx_spin_unlock( &lock );
                return;
            }
        }
        printf("##########%s: %d; Couldn't find such item\n", __FUNCTION__, __LINE__ );
        sgx_spin_unlock( &lock );
    }

    bool mDrawersAvailable[ NUM_WORKER_THREADS ];
    void* drawers[ NUM_WORKER_THREADS ]          = { NULL };
    sgx_spinlock_t lock                          = SGX_SPINLOCK_INITIALIZER;
};


class SSMContext {
public:
    SSMContext(): 
        remoteAttestationContext( -1 ),
        sessionContext          ( { 0, 0, 0, INVALID_SCHEME } ),
        attestationState        ( IDLE ),
        lastApprovedUser        ( NULL ),
        currentUserIdx          ( -1 )
    {
        RefreshSSMChallenge();
        SetupServicesTable( servicesTable );
        memset( &allowedUsersTag, 0, sizeof( allowedUsersTag ) );
    }

    OpenSSMStatus RefreshSSMChallenge()
    {
        if( SGX_SUCCESS != sgx_read_rand( ( uint8_t* )currentChallenge, sizeof( currentChallenge ) ) )
            return OPENSSM_UNEXPECTED;

        return OPENSSM_SUCCESS;
    }

    map< uint64_t, KeyObject* >     keyStore;
    vector< UserPermissions >       allowedUsers;
    sgx_aes_gcm_128bit_tag_t        allowedUsersTag;
    vector< SharedKeys >            usersSharedKeys;
    sgx_ra_context_t                remoteAttestationContext;
    SessionContext                  sessionContext;
    RemoteAttestationState          attestationState;
    UserPermissions*                lastApprovedUser;
    int                             currentUserIdx;
    Nonce                           currentChallenge;
    ServicesTable                   servicesTable;

    map< uint64_t, double >         bankRecords;
};

SSMContext ssmContext;

void PrintBuff( uint8_t* buff, uint32_t size, char *title ) {
    // sgx_spin_lock( &printSpinlock );
    printf("----------%s:\n", title);
    
    for( uint32_t i = 0; i < size; ++i )
    {
        printf("0x%02x, ", buff[ i ] );
        if( ( i + 1 ) % 8 == 0 )
            printf("\n");
    }
    printf("\n");

    // sgx_spin_unlock( &printSpinlock );
}

void empty_enclave( void )
{
	printf( "Inside Enclae!\n" );
}
/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

void EcallGetVersion( char *enclaveVersion, size_t bufferSize )
{
    size_t versionSize = strlen( OPEN_SSM_ENCLAVE_VERSION );
    size_t copySize    = versionSize < bufferSize ? versionSize : bufferSize;

    strncpy( enclaveVersion, OPEN_SSM_ENCLAVE_VERSION, copySize );
}


// This ecall is a wrapper of sgx_ra_init to create the trusted
// KE exchange key context needed for the remote attestation
// SIGMA API's. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
// @param remoteAttestationContext Pointer to the location where the returned
//                  key context is to be copied.
//
// @return Any error returned from the trusted key exchange API
//         for creating a key context.

sgx_status_t EcallInitRA( sgx_ra_context_t *remoteAttestationContext )
{
    //Linux sample code didn't use PSE (platform services)
    const bool                          DONT_USE_PLATFORM_SERVICES  = false;
    
    //Key derivation code in Linux sample was different from defualt. Therefore I opted
    //To use the defualt.
    //Default key derievation code is in implmentation of sgx_ra_proc_msg2_trusted, at 
    //sdk/tkey_exchange/tkey_exchange.cpp (currently in line 257). 
    //"derieve_key" is at common/src/ecp.cpp (currently at line 52)
    const sgx_ra_derive_secret_keys_t   USE_DEFUALT_KEY_DERIEVATION = NULL;
    
    // printf( "Inside enclave: SP Public key: $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n" );
    // uint8_t* sp_pub_key = (uint8_t*)&SERVICE_PROVIDER_PUBLIC_KEY;
    // for( uint32_t i = 0; i < sizeof( SERVICE_PROVIDER_PUBLIC_KEY ); ++i )
    // {
    //     printf( "0x%02x, ", (uint32_t)sp_pub_key[ i ] );
    //     if( ( i + 1 ) % 8 == 0 )
    //         printf( "\n" );
    // }

    
    sgx_status_t ret =  sgx_ra_init_ex( &SERVICE_PROVIDER_PUBLIC_KEY, 
                                        DONT_USE_PLATFORM_SERVICES, 
                                        USE_DEFUALT_KEY_DERIEVATION, 
                                        remoteAttestationContext );

    if( SGX_SUCCESS == ret ) {
        ssmContext.remoteAttestationContext  = *remoteAttestationContext;
        ssmContext.attestationState          = InProgress;    
    }

    return ret;
}

OpenSSMStatus GetNonce( uint8_t* dest, uint32_t size )
{
    if( size > sizeof( sgx_sha256_hash_t ) )
    {
        return OPENSSM_BAD_PARAMETER;
    }

    sgx_sha256_hash_t nonceSource;
    sgx_sha256_hash_t nonceDest;

    sgx_status_t err = SGX_SUCCESS;
    err = sgx_read_rand( ( uint8_t* )nonceSource, sizeof( nonceSource ));
    if (err != SGX_SUCCESS)
    {
        return OPENSSM_UNEXPECTED;
    }

    err = sgx_sha256_msg( ( uint8_t* )nonceSource, sizeof( nonceSource ), &nonceDest );
    if (err != SGX_SUCCESS)
    {
        return OPENSSM_UNEXPECTED;
    }

    memcpy( dest, nonceDest, size );
    return OPENSSM_SUCCESS;
}

bool IsSSMInitialized()
{
    return ssmContext.usersSharedKeys.size() > 0;
}


int LocateSharedKeys( sgx_sha256_hash_t*  userID )
{
    for( uint32_t idx = 0; idx < ssmContext.usersSharedKeys.size(); ++idx )
    {
        if( 0 == memcmp(    &ssmContext.usersSharedKeys[ idx ].userID,
                            userID,
                            sizeof( sgx_sha256_hash_t ) ) ) {
            return idx;
        }
    }

    return -1;
}

SharedKeys* LoadSharedKeys( sgx_sha256_hash_t*  userID )
{
    int userIdx = LocateSharedKeys( userID );
    if( userIdx < 0 )
        return NULL;

    ssmContext.currentUserIdx = userIdx;
    return &ssmContext.usersSharedKeys[ userIdx ];
}

OpenSSMStatus CompleteRemoteAttestationHandshake( sgx_sha256_hash_t*  userID )
{
    if( ssmContext.attestationState != UserIDApproved )
        return OPENSSM_UNEXPECTED;

    //Attestation process was successfult, the userID is approved. Make sure we have the same userID:
    //Note: even if an attacker guess right the userID (and pass this not-secure comparison), the shared secret is 
    //still unknown to her.
    if( 0 != memcmp( &ssmContext.lastApprovedUser->userID, userID, sizeof( sgx_sha256_hash_t ) ) )
        return OPENSSM_UNEXPECTED;

    SharedKeys sharedKeys = {0};
    memcpy( &sharedKeys.userID, userID, sizeof( sgx_sha256_hash_t ) );

    sgx_status_t err = SGX_SUCCESS;
    err = sgx_ra_get_keys(ssmContext.remoteAttestationContext, SGX_RA_KEY_MK, &sharedKeys.mk);
    if (err != SGX_SUCCESS)
    {
        printf("SGX error = 0x%x\n", err );
        return OPENSSM_UNEXPECTED;
    }

    err = sgx_ra_get_keys(ssmContext.remoteAttestationContext, SGX_RA_KEY_SK, &sharedKeys.sk);
    if (err != SGX_SUCCESS)
    {
        return OPENSSM_UNEXPECTED;
    }

    ssmContext.usersSharedKeys.push_back( sharedKeys );
    memset_s( &sharedKeys, sizeof( sharedKeys ), 0, sizeof( sharedKeys ) );
    ssmContext.attestationState = IDLE;
    return OPENSSM_SUCCESS;
}

OpenSSMStatus DeriveKey_AES_CMAC( sgx_cmac_128bit_key_t   *baseKey, 
                                  uint16_t                label,  
                                  uint8_t*                context,
                                  uint32_t                contextSize,
                                  sgx_cmac_128bit_tag_t*  derivedKey )
{
    const uint8_t COUNTER           = 1;
    const uint8_t ZERO              = 0;
    const uint16_t KEY_LENGTH_128    = 0x80;

    sgx_cmac_state_handle_t cmacContext;
    if( SGX_SUCCESS != sgx_cmac128_init( baseKey, &cmacContext ) )
        return OPENSSM_SECURE_MSG_UNEXPECTED_ERROR;

    if( SGX_SUCCESS != sgx_cmac128_update( ( uint8_t* )&COUNTER,        sizeof( COUNTER ),          cmacContext ) ||
        SGX_SUCCESS != sgx_cmac128_update( ( uint8_t* )&label,          sizeof( label ),            cmacContext ) ||
        SGX_SUCCESS != sgx_cmac128_update( ( uint8_t* )&ZERO,           sizeof( ZERO ),            cmacContext ) ||
        SGX_SUCCESS != sgx_cmac128_update( ( uint8_t* )context,         contextSize,                cmacContext ) ||
        SGX_SUCCESS != sgx_cmac128_update( ( uint8_t* )&KEY_LENGTH_128, sizeof( KEY_LENGTH_128 ),   cmacContext ) ||
        SGX_SUCCESS != sgx_cmac128_final (cmacContext, derivedKey ) ) 
    {
        sgx_cmac128_close( cmacContext );
        return OPENSSM_SECURE_MSG_UNEXPECTED_ERROR;
    }

    return OPENSSM_SUCCESS;
}

OpenSSMStatus  DeriveSessionKey( sgx_sha256_hash_t*  userID, uint8_t*  remoteNonce, uint8_t* ssmNonce )
{
    KeyDerivationData keyDerivationData;
    keyDerivationData.counter               = 1;
    keyDerivationData.alwaysZero            = 0;
    keyDerivationData.lengthOfDerivedKey    = 0x80; //128 bit

    memcpy( &keyDerivationData.label, "EK", sizeof( "EK" ) - 1 ); //Lable: ephemeral key
    memcpy( keyDerivationData.context, remoteNonce, AES_GCM_128_DOUBLE_NONCE_PAYLOAD_SIZE );
    memcpy( keyDerivationData.context + AES_GCM_128_DOUBLE_NONCE_PAYLOAD_SIZE, ssmNonce, AES_GCM_128_DOUBLE_NONCE_PAYLOAD_SIZE );

    SharedKeys* sharedKeys = LoadSharedKeys( userID );
    if( NULL == sharedKeys )
        return OPENSSM_ESTABLISH_SESSION_FAILED_UNEXPECTED;
    
    sgx_status_t err = sgx_rijndael128_cmac_msg(    &sharedKeys->sk,                 //Diffie hellman key from remote attestation process
                                                    ( uint8_t* )&keyDerivationData, 
                                                    sizeof( KeyDerivationData ),  
                                                    &ssmContext.sessionContext.sessionKey  );
    
    if (err != SGX_SUCCESS)
        return OPENSSM_ESTABLISH_SESSION_FAILED_UNEXPECTED;

    return OPENSSM_SUCCESS;
}

OpenSSMStatus GenerateSSMProofOfIdentity(   sgx_sha256_hash_t*      userID,
                                            sgx_cmac_128bit_tag_t*  ssmProofOfIdentity )
{
    if( NULL == userID )
        return OPENSSM_UNEXPECTED;

    SharedKeys *securityOfficerKeys = &ssmContext.usersSharedKeys[ 0 ];
    sgx_status_t err = sgx_rijndael128_cmac_msg(    &securityOfficerKeys->mk,                
                                                    ( uint8_t* )userID, 
                                                    sizeof( sgx_sha256_hash_t ),  
                                                    ssmProofOfIdentity  );
    if (err != SGX_SUCCESS)
        return OPENSSM_UNEXPECTED;

    return OPENSSM_SUCCESS;
}

UserPermissions* FindUserPermissions( UserID *userID  )
{
    for( uint32_t idx = 0; idx < ssmContext.allowedUsers.size(); ++idx )
    {
        //This memcmp is not time constant. That is OK.
        if( 0 == memcmp(    &ssmContext.allowedUsers[ idx ].userID,
                            userID,
                            sizeof( sgx_sha256_hash_t ) ) ) {
            return &ssmContext.allowedUsers[ idx ];
        }
    }

    return NULL;
}


OpenSSMStatus EcallEstablishSession(    sgx_sha256_hash_t*      userID, 
                                        uint16_t                scheme, 
                                        uint8_t*                remoteNonce, 
                                        uint8_t*                ssmNonce,
                                        size_t                  payloadSize )
{
    if( scheme == SessionKeysScheme::KEY_SCHEME_NULL_ENCRYPTION ) {
        ssmContext.sessionContext.scheme = NULL_ENCRYPTION;
        return OPENSSM_SUCCESS;
    }

    if( scheme != SessionKeysScheme::AES_GCM_128_DOUBLE_NONCE )
        return OPENSSM_ESTABLISH_SESSION_FAILED_BAD_SCHEME;
 
    if( payloadSize != AES_GCM_128_DOUBLE_NONCE_PAYLOAD_SIZE )
        return OPENSSM_ESTABLISH_SESSION_FAILED_BAD_MSG;
 
    if( OPENSSM_SUCCESS != GetNonce( ssmNonce, AES_GCM_128_DOUBLE_NONCE_PAYLOAD_SIZE ) )
        return OPENSSM_ESTABLISH_SESSION_FAILED_UNEXPECTED;

    if( ssmContext.attestationState == UserIDApproved ) {
        if( OPENSSM_SUCCESS != CompleteRemoteAttestationHandshake( userID ) )
                return OPENSSM_ESTABLISH_SESSION_FAILED_UNEXPECTED;
    }
    else if( ssmContext.attestationState != IDLE )
        return OPENSSM_ESTABLISH_SESSION_FAILED_UNEXPECTED;

    if( OPENSSM_SUCCESS != DeriveSessionKey( userID, remoteNonce, ssmNonce ) )
        return OPENSSM_ESTABLISH_SESSION_FAILED_UNEXPECTED;
    
    ssmContext.sessionContext.decryptionIV.label      = DECRYPTION_IV;
    ssmContext.sessionContext.decryptionIV.msgCounter = 0;

    ssmContext.sessionContext.encryptionIV.label      = ENCRYPTION_IV;
    ssmContext.sessionContext.encryptionIV.msgCounter = 0;

    ssmContext.sessionContext.scheme = AES_GCM_128;

    ssmContext.lastApprovedUser = FindUserPermissions( ( UserID* )userID );
    if( NULL == ssmContext.lastApprovedUser )
        return OPENSSM_ESTABLISH_SESSION_FAILED_UNEXPECTED;

    return OPENSSM_SUCCESS;
}

OpenSSMStatus DecryptSecureMsg( EncryptedMsg* encryptedMsg, SecureMsg* secureMsg )
{
    if( ssmContext.sessionContext.scheme == NULL_ENCRYPTION ) {
        memcpy( secureMsg->asBuffer, encryptedMsg->ciphertext, encryptedMsg->cipherSize );
        return OPENSSM_SUCCESS;
    }

    const uint8_t* NO_ADD_POINTER = NULL;
    const uint32_t NO_ADD_LENGTH  = 0;

    sgx_spin_lock( &decryptionSpinlock );
    // ssmContext.sessionContext.decryptionIV.msgCounter++;
    ssmContext.sessionContext.decryptionIV.msgCounter = encryptedMsg->msgNumber;
    sgx_status_t err = sgx_rijndael128GCM_decrypt( &ssmContext.sessionContext.sessionKey,
                                                    encryptedMsg->ciphertext,
                                                    encryptedMsg->cipherSize,
                                                    secureMsg->asBuffer,
                                                    ( uint8_t* )&ssmContext.sessionContext.decryptionIV,
                                                    sizeof( ssmContext.sessionContext.decryptionIV ),
                                                    NO_ADD_POINTER,
                                                    NO_ADD_LENGTH,
                                                    &encryptedMsg->mac );
    
    if( err == SGX_ERROR_MAC_MISMATCH ) {
        ssmContext.sessionContext.decryptionIV.msgCounter--;
        sgx_spin_unlock( &decryptionSpinlock );
        return OPENSSM_ENCRYPTED_MSG_FAILED_BAD_MAC;
    } 
    
    sgx_spin_unlock( &decryptionSpinlock );
    
    if( err != SGX_SUCCESS ){
        ssmContext.sessionContext.decryptionIV.msgCounter--;
        return OPENSSM_ENCRYPTED_MSG_FAILED_UNEXPECTED;
    }
    
    return OPENSSM_SUCCESS;
}


OpenSSMStatus EncryptSecureMsg( SecureMsg* secureMsg, uint16_t secureMsgSize, EncryptedMsg* encryptedMsg )
{
    const uint8_t* NO_ADD_POINTER = NULL;
    const uint32_t NO_ADD_LENGTH  = 0;

    encryptedMsg->cipherSize = secureMsgSize;

    if( ssmContext.sessionContext.scheme == NULL_ENCRYPTION ) {
        memcpy( encryptedMsg->ciphertext, secureMsg->asBuffer, secureMsgSize );
        return OPENSSM_SUCCESS;
    }

    sgx_spin_lock( &encryptionSpinlock );
    ssmContext.sessionContext.encryptionIV.msgCounter++;
    sgx_status_t err = sgx_rijndael128GCM_encrypt( &ssmContext.sessionContext.sessionKey,
                                                    secureMsg->asBuffer,
                                                    secureMsgSize,
                                                    encryptedMsg->ciphertext,
                                                    ( uint8_t* )&ssmContext.sessionContext.encryptionIV,
                                                    sizeof( ssmContext.sessionContext.encryptionIV ),
                                                    NO_ADD_POINTER,
                                                    NO_ADD_LENGTH,
                                                    &encryptedMsg->mac );
    
    if( err != SGX_SUCCESS ){
        ssmContext.sessionContext.encryptionIV.msgCounter--;
        sgx_spin_unlock( &encryptionSpinlock );
        return OPENSSM_ENCRYPTED_MSG_FAILED_UNEXPECTED;
    }
    
    encryptedMsg->msgNumber = ssmContext.sessionContext.encryptionIV.msgCounter;
    sgx_spin_unlock( &encryptionSpinlock );    

    return OPENSSM_SUCCESS;
}


OpenSSMStatus ReportErrorInSecureMsg(   SecureMsg*      secureMsg, 
                                        EncryptedMsg*   encryptedMsg, 
                                        size_t          maxResponseSize,
                                        OpenSSMStatus   errorCode )
{
    uint32_t responseSize = sizeof( EncryptedMsg )                  + 
                            sizeof( SecureMsgType )                 + 
                            sizeof( SecureErrorMsg );
    if( responseSize > maxResponseSize )
        return OPENSSM_ENCRYPTED_MSG_FAILED_RESPONSE_BUFFER_TOO_SMALL;
    
    secureMsg->type           = ERROR_MSG;
    SecureErrorMsg* errorMsg  = ( SecureErrorMsg* )secureMsg->body;
    errorMsg->errorCode       = errorCode;

    uint32_t secureMsgSize = responseSize - sizeof( EncryptedMsg );
    return EncryptSecureMsg( secureMsg, secureMsgSize, encryptedMsg );
}

OpenSSMStatus HandleImportRSAKey_verifySize( SecureMsg* secureMsg, uint32_t secureMsgSize )
{
    if( secureMsgSize < sizeof( SecureMsgType ) + sizeof( RSAGenerateKeyPairMsg ) )
        return OPENSSM_ENCRYPTED_MSG_FAILED_BAD_MSG;

    ImportRSAKeyMsg* importKey  = ( ImportRSAKeyMsg* )secureMsg->body;
    uint32_t expectedTotalSize         =    sizeof( SecureMsgType )             + 
                                            sizeof( ImportRSAKeyMsg )     + 
                                            importKey->privateKeySize;

    if( expectedTotalSize != secureMsgSize )
        return OPENSSM_ENCRYPTED_MSG_FAILED_BAD_MSG;

    return OPENSSM_SUCCESS;
}

OpenSSMStatus HandleGenerateKeyPairRSA_verifySize( SecureMsg* secureMsg, uint32_t secureMsgSize )
{
    if( secureMsgSize < sizeof( SecureMsgType ) + sizeof( RSAGenerateKeyPairMsg ) )
        return OPENSSM_ENCRYPTED_MSG_FAILED_BAD_MSG;

    RSAGenerateKeyPairMsg* genKeyPair  = ( RSAGenerateKeyPairMsg* )secureMsg->body;
    uint32_t expectedTotalSize         =    sizeof( SecureMsgType )             + 
                                            sizeof( RSAGenerateKeyPairMsg )     + 
                                            genKeyPair->publicExponentSize;

    if( expectedTotalSize != secureMsgSize )
        return OPENSSM_ENCRYPTED_MSG_FAILED_BAD_MSG;

    return OPENSSM_SUCCESS;
}


OpenSSMStatus HandleGenerateKeyPairECDSA_OpenSSL_verifySize( SecureMsg* secureMsg, uint32_t secureMsgSize )
{
    if( secureMsgSize != sizeof( SecureMsgType ) + sizeof( ECDSA_GenerateKeyPairOpenSSLMsg ) )
        return OPENSSM_ENCRYPTED_MSG_FAILED_BAD_MSG;

    return OPENSSM_SUCCESS;
}


OpenSSMStatus HandleArmKey_verifySize( SecureMsg* secureMsg, uint32_t secureMsgSize )
{
    if( secureMsgSize < sizeof( SecureMsgType ) + sizeof( ArmKeyRequest ) )
        return OPENSSM_ENCRYPTED_MSG_FAILED_BAD_MSG;
 
    ArmKeyRequest   *armKeyMsg       = ( ArmKeyRequest* )secureMsg->body;
    uint32_t        totalTokensSize  = armKeyMsg->sharedCustodySpec.numParticipants * sizeof( ProtectionToken );                                          
    if( secureMsgSize !=    sizeof( SecureMsgType )             +    
                            sizeof( ArmKeyRequest )             +  
                            totalTokensSize )
        return OPENSSM_ENCRYPTED_MSG_FAILED_BAD_MSG;
 
    return OPENSSM_SUCCESS;
}

OpenSSMStatus HandleGenerateKeyPairECDSA_verifySize( SecureMsg* secureMsg, uint32_t secureMsgSize )
{
    if( secureMsgSize < sizeof( SecureMsgType ) + sizeof( ECDSA_GenerateKeyPairMsg ) )
        return OPENSSM_ENCRYPTED_MSG_FAILED_BAD_MSG;
 
    ECDSA_GenerateKeyPairMsg* genKeyPair   = ( ECDSA_GenerateKeyPairMsg* )secureMsg->body;
    if( false == genKeyPair->attributes.storeOnDisk )
        return OPENSSM_SUCCESS;
 
    if( secureMsgSize < sizeof( SecureMsgType )             + 
                        sizeof( ECDSA_GenerateKeyPairMsg )  + 
                        sizeof( SharedCustodySpec ) )
        return OPENSSM_ENCRYPTED_MSG_FAILED_BAD_MSG;  

    SharedCustodySpec* sharedCustudySpec    =  (SharedCustodySpec*) ( (uint8_t*)secureMsg + 
                                                                    sizeof( SecureMsgType ) + 
                                                                    sizeof( ECDSA_GenerateKeyPairMsg ) );
    uint32_t totalTokensSize                = sharedCustudySpec->numParticipants * sizeof( ProtectionToken );                                          
    if( secureMsgSize !=    sizeof( SecureMsgType )             +    
                            sizeof( ECDSA_GenerateKeyPairMsg )  +  
                            sizeof( SharedCustodySpec )         + 
                            totalTokensSize )
        return OPENSSM_ENCRYPTED_MSG_FAILED_BAD_MSG;
 
    return OPENSSM_SUCCESS;
}

OpenSSMStatus HandleGenerateKeyAES_GCM_verifySize( SecureMsg* secureMsg, uint32_t secureMsgSize )
{
    if( secureMsgSize != sizeof( SecureMsgType ) + sizeof( AES_GCM_GenerateKeyMsg ) )
        return OPENSSM_ENCRYPTED_MSG_FAILED_BAD_MSG;

    return OPENSSM_SUCCESS;
}
uint64_t HandleGenerateKeyPairRSA_computeHandle( uint8_t* serilizedPublicKey, int publicKeySize )
{
    sgx_sha256_hash_t sha256 = {0};

    if( SGX_SUCCESS != sgx_sha256_msg(  serilizedPublicKey, 
                                        ( uint32_t )publicKeySize, 
                                        &sha256 ) )
        return 0;
    
    uint64_t handle = 0;
    memcpy( &handle, sha256, sizeof( handle ) );

    return handle;
}

uint64_t HandleGenerateKeyPairECDSA_computeHandle( sgx_ec256_public_t*       publicKey )
{
    sgx_sha256_hash_t sha256 = {0};

    if( SGX_SUCCESS != sgx_sha256_msg(  ( uint8_t* ) publicKey, 
                                        sizeof( sgx_ec256_public_t ), 
                                        &sha256 ) )
        return 0;

    uint64_t handle = 0;
    memcpy( &handle, sha256, sizeof( handle ) );

    return handle;
}

EVP_PKEY* CreateEVPKey( RSA* keyPair )
{
    const int SUCCESS = 1;

    EVP_PKEY* evpKey = EVP_PKEY_new();
    if(evpKey == NULL) 
        return NULL;

    if( SUCCESS != EVP_PKEY_assign_RSA( evpKey, keyPair ) )
    {
        EVP_PKEY_free( evpKey );
        return NULL;
    }

    return evpKey;
}

EVP_PKEY* CreateEVPKey( EC_KEY* keyPair )
{
    const int SUCCESS = 1;

    EVP_PKEY* evpKey = EVP_PKEY_new();
    if(evpKey == NULL) 
        return NULL;

    if( SUCCESS != EVP_PKEY_assign_EC_KEY( evpKey, keyPair ) )
    {
        EVP_PKEY_free( evpKey );
        return NULL;
    }

    return evpKey;
}

uint64_t GetRandomHandle()
{
    uint8_t           randomBuffer      [ 32 ];

    if( SGX_SUCCESS != sgx_read_rand( randomBuffer, sizeof( randomBuffer ) ) )
        return 0;

    sgx_sha256_hash_t sha256 = {0};

    if( SGX_SUCCESS != sgx_sha256_msg(  ( uint8_t* ) randomBuffer, 
                                        sizeof( randomBuffer ), 
                                        &sha256 ) )
        return 0;

    uint64_t handle = 0;
    memcpy( &handle, sha256, sizeof( handle ) );

    return handle;
}

uint64_t HandleGenerateKeyPairAES_GCM_generateHandle()
{
    return GetRandomHandle();
    // uint8_t           randomBuffer      [ 32 ];

    // if( SGX_SUCCESS != sgx_read_rand( randomBuffer, sizeof( randomBuffer ) ) )
    //     return 0;

    // sgx_sha256_hash_t sha256 = {0};

    // if( SGX_SUCCESS != sgx_sha256_msg(  ( uint8_t* ) randomBuffer, 
    //                                     sizeof( randomBuffer ), 
    //                                     &sha256 ) )
    //     return 0;

    // uint64_t handle = 0;
    // memcpy( &handle, sha256, sizeof( handle ) );

    // return handle;
}

OpenSSMStatus HandleImportRSAKey_storeAndreply( EVP_PKEY*           evpKey,
                                                SecureMsg*          secureMsg, 
                                                EncryptedMsg*       encryptedMsg, 
                                                size_t              maxResponseSize )
{
    secureMsg->type                          = MK_RESPONSE(IMPORT_RSA_KEY);
    ImportRSAKeyResponse* importKeyResponse  = ( ImportRSAKeyResponse* )secureMsg->body;
    //Serialize public key:
    uint8_t* serilizedPublicKey = NULL;
    int      publicKeySize      = i2d_PUBKEY( evpKey, &serilizedPublicKey );
    if( publicKeySize <= 0 )
        return OPENSSM_ENCRYPTED_MSG_FAILED_UNEXPECTED;
           
    //Ensure we have room to reply with public key:
    uint32_t responseSize = sizeof( EncryptedMsg )                  + 
                            sizeof( SecureMsgType )                 + 
                            sizeof( ImportRSAKeyResponse );

    if( responseSize > maxResponseSize ){
        free( serilizedPublicKey );
        return OPENSSM_ENCRYPTED_MSG_FAILED_RESPONSE_BUFFER_TOO_SMALL;
    }

    importKeyResponse->keyHandle = HandleGenerateKeyPairRSA_computeHandle( serilizedPublicKey, publicKeySize );    
    free( serilizedPublicKey );

    if( 0 == importKeyResponse->keyHandle ) 
        return  ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_UNEXPECTED_ERROR );

    //Store key:
    KeyObject *keyObject                        = new KeyObject();
    keyObject->type                             = RSA_KEY;
    keyObject->attributes.value                 = 0;
    keyObject->attributes.canBeUsedForSigning   = true;
    keyObject->handle                           = importKeyResponse->keyHandle;
    keyObject->object                           = evpKey;
    ssmContext.keyStore[ keyObject->handle ]    = keyObject;

    //Encrypt reply:
    uint32_t secureMsgSize = responseSize - sizeof( EncryptedMsg );

    return EncryptSecureMsg( secureMsg, secureMsgSize, encryptedMsg );
}

EVP_PKEY* DuplicateEVPKey( EVP_PKEY* evpKey, KeyObjectType type )
{
    if( type == RSA_KEY ){
        RSA *rsa             = EVP_PKEY_get1_RSA( evpKey ); // Get the underlying RSA key
        RSA *dup_rsa         = RSAPrivateKey_dup(rsa); // Duplicate the RSA key
        EVP_PKEY *rsaKeyCopy = CreateEVPKey( dup_rsa );

        return rsaKeyCopy;
    }

    else if( type == ECDSA_OPENSSL_KEY ) {
        EC_KEY*   ecKey       = EVP_PKEY_get1_EC_KEY( evpKey );
        EC_KEY*   dup_ecKey   = EC_KEY_dup( ecKey );
        EVP_PKEY* ecKeyCopy   = CreateEVPKey( dup_ecKey );

        return ecKeyCopy;
    }

    return NULL;
}

DrawerManager* GenerateDrawersFromEVPKey( EVP_PKEY* evpKey, KeyObjectType type )
{
    DrawerManager* drawerManager = new DrawerManager();
    
    for( int i(0); i < NUM_WORKER_THREADS; i++ ) {
        drawerManager->drawers[ i ] = DuplicateEVPKey( evpKey, type );
        if( NULL == drawerManager->drawers[ i ] ){
            printf("############# %s: %d; Error duplicating key\n", __FUNCTION__, __LINE__ );
            return NULL;
        }
    }

    return drawerManager;
}

OpenSSMStatus HandleGenerateKeyPairECDSA_OpenSSL_storeAndreply( EC_KEY*             keyPair,
                                                                KeyAttributes       attributes,
                                                                SecureMsg*          secureMsg, 
                                                                EncryptedMsg*       encryptedMsg, 
                                                                size_t              maxResponseSize )
{

    secureMsg->type                                        = MK_RESPONSE( ECDSA_GENERATE_KEY_PAIR_OPENSSL );
    ECDSA_GenerateKeyPairOpenSSLResponseMsg* publicKeyMsg  = ( ECDSA_GenerateKeyPairOpenSSLResponseMsg* )secureMsg->body;

    EVP_PKEY* evpKey = CreateEVPKey( keyPair );
    if( NULL == evpKey )
        return  ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_UNEXPECTED_ERROR );

    //Serialize public key:
    uint8_t* serilizedPublicKey = NULL;
    int      publicKeySize      = i2d_PUBKEY( evpKey, &serilizedPublicKey );
    if( publicKeySize <= 0 )
        return OPENSSM_ENCRYPTED_MSG_FAILED_UNEXPECTED;

    //Ensure we have room to reply with public key:
    uint32_t responseSize = sizeof( EncryptedMsg )                            + 
                            sizeof( SecureMsgType )                           + 
                            sizeof( ECDSA_GenerateKeyPairOpenSSLResponseMsg ) +
                            publicKeySize;

    if( responseSize > maxResponseSize ){
        free( serilizedPublicKey );
        return OPENSSM_ENCRYPTED_MSG_FAILED_RESPONSE_BUFFER_TOO_SMALL;
    }

    //Copy pulic key:
    
    // PrintBuff( serilizedPublicKey, publicKeySize, (char*)"public key" );
    memcpy( publicKeyMsg->publicKey, serilizedPublicKey, publicKeySize );
    
    publicKeyMsg->publicKeySize   = publicKeySize;
    //using the RSA function HandleGenerateKeyPairRSA_computeHandle is ok:
    publicKeyMsg->handle          = HandleGenerateKeyPairRSA_computeHandle( serilizedPublicKey, publicKeySize );    
    free( serilizedPublicKey );
    
    if( 0 == publicKeyMsg->handle ) 
        return  ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_UNEXPECTED_ERROR );
    
    //Store key:
    KeyObject *keyObject  = new KeyObject();
    keyObject->type       = ECDSA_OPENSSL_KEY;
    keyObject->attributes = attributes;
    keyObject->handle     = publicKeyMsg->handle;
    keyObject->object     = GenerateDrawersFromEVPKey( evpKey, ECDSA_OPENSSL_KEY );
    ssmContext.keyStore[ keyObject->handle ] = keyObject;

    //Encrypt reply:
    uint32_t secureMsgSize = responseSize - sizeof( EncryptedMsg );
    return EncryptSecureMsg( secureMsg, secureMsgSize, encryptedMsg );
}

OpenSSMStatus HandleGenerateKeyPairRSA_storeAndreply(   RSA*                keyPair,
                                                        X509*               certificate,
                                                        KeyAttributes       attributes,
                                                        SecureMsg*          secureMsg, 
                                                        EncryptedMsg*       encryptedMsg, 
                                                        size_t              maxResponseSize )
{
    secureMsg->type                              = MK_RESPONSE( RSA_GENERATE_KEY_PAIR );
    RSAGenerateKeyPairResponseMsg* publicKeyMsg  = ( RSAGenerateKeyPairResponseMsg* )secureMsg->body;
    
    EVP_PKEY* evpKey = CreateEVPKey( keyPair );
    if( NULL == evpKey )
        return  ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_UNEXPECTED_ERROR );
    
    //Serialize public key:
    uint8_t* serilizedPublicKey = NULL;
    int      publicKeySize      = i2d_PUBKEY( evpKey, &serilizedPublicKey );
    if( publicKeySize <= 0 )
        return OPENSSM_ENCRYPTED_MSG_FAILED_UNEXPECTED;
    
    uint8_t* serializedCertificate  = NULL;
    int      certificateSize        = i2d_X509( certificate, &serializedCertificate );
    if (certificateSize < 0) {
        free( serilizedPublicKey );
        return OPENSSM_ENCRYPTED_MSG_FAILED_UNEXPECTED;
    }
    
    //Ensure we have room to reply with public key:
    uint32_t responseSize = sizeof( EncryptedMsg )                  + 
                            sizeof( SecureMsgType )                 + 
                            sizeof( RSAGenerateKeyPairResponseMsg ) +
                            publicKeySize                           + 
                            certificateSize; 
    if( responseSize > maxResponseSize ){
        free( serilizedPublicKey );
        return OPENSSM_ENCRYPTED_MSG_FAILED_RESPONSE_BUFFER_TOO_SMALL;
    }

    //Copy pulic key:
    memcpy( publicKeyMsg->publicKeyAndCertificate, serilizedPublicKey, publicKeySize );
    memcpy( publicKeyMsg->publicKeyAndCertificate + publicKeySize, serializedCertificate, certificateSize );
    publicKeyMsg->publicKeySize   = publicKeySize;
    publicKeyMsg->certificateSize = certificateSize;
    publicKeyMsg->handle          = HandleGenerateKeyPairRSA_computeHandle( serilizedPublicKey, publicKeySize );    
    free( serilizedPublicKey );
    free( serializedCertificate );
    
    if( 0 == publicKeyMsg->handle ) 
        return  ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_UNEXPECTED_ERROR );
    
    
    //Store key:
    KeyObject *keyObject  = new KeyObject();
    keyObject->type       = RSA_KEY;
    keyObject->attributes = attributes;
    keyObject->handle     = publicKeyMsg->handle;
    keyObject->object     = GenerateDrawersFromEVPKey( evpKey, RSA_KEY );
    ssmContext.keyStore[ keyObject->handle ] = keyObject;

    //Encrypt reply:
    uint32_t secureMsgSize = responseSize - sizeof( EncryptedMsg );
    return EncryptSecureMsg( secureMsg, secureMsgSize, encryptedMsg );
}

OpenSSMStatus StoreKeyInLiveStorage(    KeyObjectType   keyType, 
                                        KeyAttributes   attributes,
                                        uint64_t        keyHandle, 
                                        void*           key  )
{
    if( 0 == keyHandle ) 
        return  OPENSSM_SECURE_MSG_UNEXPECTED_ERROR;

     //Store key:
    KeyObject *keyObject  = new KeyObject();
    keyObject->type       = keyType;
    keyObject->attributes = attributes;
    keyObject->handle     = keyHandle;
    keyObject->object     = key;

    if( NULL == keyObject->object )
        return  OPENSSM_SECURE_MSG_UNEXPECTED_ERROR;

    ssmContext.keyStore[ keyObject->handle ] = keyObject;

    return OPENSSM_SUCCESS;
}

OpenSSMStatus HandleGenerateKeyPairECDSA_reply( sgx_ec256_public_t*       publicKey ,
                                                uint64_t                  keyHandle,
                                                SecureMsg*                secureMsg, 
                                                EncryptedMsg*             encryptedMsg, 
                                                size_t                    maxResponseSize )
{
    secureMsg->type                                 = MK_RESPONSE(ECDSA_GENERATE_KEY_PAIR);
    ECDSA_GenerateKeyPairResponseMsg* publicKeyMsg  = ( ECDSA_GenerateKeyPairResponseMsg* )secureMsg->body;

    //Ensure we have room to reply with public key:
    uint32_t responseSize = sizeof( EncryptedMsg )                  + 
                            sizeof( SecureMsgType )                 + 
                            sizeof( ECDSA_GenerateKeyPairResponseMsg );
                             
    if( responseSize > maxResponseSize ){
        return OPENSSM_ENCRYPTED_MSG_FAILED_RESPONSE_BUFFER_TOO_SMALL;
    }

    //Copy pulic key:
    memcpy( &publicKeyMsg->publicKey, publicKey, sizeof( sgx_ec256_public_t ) );
    publicKeyMsg->handle = keyHandle;

    //Encrypt reply:
    uint32_t secureMsgSize = responseSize - sizeof( EncryptedMsg );
    return EncryptSecureMsg( secureMsg, secureMsgSize, encryptedMsg );
}

OpenSSMStatus ReplyWithoutPayload(  SecureMsgType             msgType,
                                    SecureMsg*                secureMsg, 
                                    EncryptedMsg*             encryptedMsg, 
                                    size_t                    maxResponseSize )
{
    secureMsg->type = msgType;
   
    //Ensure we have room to reply:
    uint32_t responseSize = sizeof( EncryptedMsg ) + 
                            sizeof( SecureMsgType );   
                             
    if( responseSize > maxResponseSize ){
        return OPENSSM_ENCRYPTED_MSG_FAILED_RESPONSE_BUFFER_TOO_SMALL;
    }

    //Encrypt reply:
    uint32_t secureMsgSize = responseSize - sizeof( EncryptedMsg );
    return EncryptSecureMsg( secureMsg, secureMsgSize, encryptedMsg );
}

OpenSSMStatus HandleGenerateKeyAES_GCM_storeAndreply(   AES_KEY*                  aesKey, 
                                                        uint16_t                  keySizeInBits,
                                                        KeyAttributes             attributes,
                                                        SecureMsg*                secureMsg, 
                                                        EncryptedMsg*             encryptedMsg, 
                                                        size_t                    maxResponseSize )
{
    secureMsg->type                                 = MK_RESPONSE(AES_GCM_GENERATE_KEY);
    AES_GCM_GenerateKeyResponseMsg* symmetricKeyMsg = ( AES_GCM_GenerateKeyResponseMsg* )secureMsg->body;

    //Ensure we have room to reply with public key:
    uint32_t responseSize = sizeof( EncryptedMsg )                  + 
                            sizeof( SecureMsgType )                 + 
                            sizeof( AES_GCM_GenerateKeyResponseMsg );
                             
    if( responseSize > maxResponseSize ){
        return OPENSSM_ENCRYPTED_MSG_FAILED_RESPONSE_BUFFER_TOO_SMALL;
    }

    symmetricKeyMsg->handle        = HandleGenerateKeyPairAES_GCM_generateHandle();  
    if( 0 == symmetricKeyMsg->handle ) 
        return  ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_UNEXPECTED_ERROR );

    //Store key:
    KeyObject *keyObject  = new KeyObject();
    keyObject->type       = keySizeInBits; //keySize is exactly the enum value of AES_KEY_1128, AES_KEY_192, AES_KEY_256
    keyObject->attributes = attributes;
    keyObject->handle     = symmetricKeyMsg->handle;
    keyObject->object     = malloc( sizeof( AES_GCM_128_Context ) );
    if( NULL == keyObject->object )
        return  ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_UNEXPECTED_ERROR );

    AES_GCM_128_Context *aesContext = ( AES_GCM_128_Context* )keyObject->object;
    memcpy( &aesContext->key, aesKey, sizeof( AES_KEY ) );
    memset_s( &aesKey, sizeof( AES_KEY ), 0 , sizeof( AES_KEY )  );
    if( SGX_SUCCESS != sgx_read_rand( aesContext->iv.asBytes, sizeof( AES_GCM_IV ) ) )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_UNEXPECTED_ERROR );

    ssmContext.keyStore[ keyObject->handle ] = keyObject;

    //Encrypt reply:
    uint32_t secureMsgSize = responseSize - sizeof( EncryptedMsg );
    return EncryptSecureMsg( secureMsg, secureMsgSize, encryptedMsg );
}

OpenSSMStatus HandleGenerateKeyPairRSA_generateKey( RSA** keyPair, RSAGenerateKeyPairMsg* genKeyPair )
{
    BIGNUM* CREATE_NEW_BIGNUM = NULL;
    BIGNUM* publicExponent    = BN_bin2bn(  genKeyPair->publicExponent, 
                                            genKeyPair->publicExponentSize, 
                                            CREATE_NEW_BIGNUM );
    if( publicExponent == NULL )
        return OPENSSM_SECURE_MSG_UNEXPECTED_ERROR;
    
    *keyPair = RSA_new();
    if( NULL == RSA_generate_key_ex( *keyPair, genKeyPair->modulusBits, publicExponent, NULL ) ) {
        RSA_free( *keyPair );
        BN_free ( publicExponent );
        *keyPair = NULL;
        return OPENSSM_SECURE_MSG_UNEXPECTED_ERROR;
    }

    BN_free ( publicExponent );

    return OPENSSM_SUCCESS;
}

OpenSSMStatus HandleGenerateKeyPairECDSA_OpenSSL_generateKey( EC_KEY** keyPair, ECDSA_GenerateKeyPairOpenSSLMsg* genKeyPair )
{
    const int      SUCCESS                  = 1;
    

    if(NULL == ( *keyPair = EC_KEY_new_by_curve_name( genKeyPair->curveNID )))
        return OPENSSM_SECURE_MSG_UNEXPECTED_ERROR;

    if( SUCCESS != EC_KEY_generate_key( *keyPair ) )
        return OPENSSM_SECURE_MSG_UNEXPECTED_ERROR;

    return OPENSSM_SUCCESS;
    
}

OpenSSMStatus HandleGenerateKeyPairECDSA_generateKey(   sgx_ec256_private_t*      privateKey, 
                                                        sgx_ec256_public_t*       publicKey   )
{
    sgx_ecc_state_handle_t context;
    if( SGX_SUCCESS !=  sgx_ecc256_open_context( &context) )
        return OPENSSM_SECURE_MSG_UNEXPECTED_ERROR;
 
    if( SGX_SUCCESS !=  sgx_ecc256_create_key_pair( privateKey, publicKey, context) )
        return OPENSSM_SECURE_MSG_UNEXPECTED_ERROR;

    if( SGX_SUCCESS !=  sgx_ecc256_close_context( context ) )
        return OPENSSM_SECURE_MSG_UNEXPECTED_ERROR;
    
    return OPENSSM_SUCCESS;
}


/* Add extension using V3 code: we can set the config file as NULL
 * because we wont reference any other sections.
 */

int add_ext(X509 *cert, int nid, char *value)
{
    X509_EXTENSION *ex;
    X509V3_CTX ctx;
    /* This sets the 'context' of the extensions. */
    /* No configuration database */
    X509V3_set_ctx_nodb(&ctx);
    /* Issuer and subject certs: both the target since it is self signed,
     * no request and no CRL
     */
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ex)
        return 0;

    X509_add_ext(cert,ex,-1);
    X509_EXTENSION_free(ex);
    return 1;
}

OpenSSMStatus HandleGenerateKeyPairRSA_createX509Cert( RSA *keyPair, X509 **x509, time_t now )
{
    const int NUM_DAYS      = 365;
    int SERIAL_NUMBER = 0;

    sgx_read_rand( (uint8_t*)&SERIAL_NUMBER, sizeof( int ) );
    EVP_PKEY *evpKey = CreateEVPKey( RSAPrivateKey_dup( keyPair ) );
    if( NULL == x509 || NULL == evpKey )
        return OPENSSM_UNEXPECTED;
    
    *x509 = X509_new();
    if( NULL == *x509 ) {
        EVP_PKEY_free( evpKey );
        return OPENSSM_UNEXPECTED;
    }

    X509* certificate = *x509;
    X509_set_version(certificate,2);
    ASN1_INTEGER_set(X509_get_serialNumber( certificate ),SERIAL_NUMBER);
    EnclaveSetTime( now );
    
    X509_gmtime_adj(X509_get_notBefore( certificate ),( long )0);
    X509_gmtime_adj(X509_get_notAfter( certificate ),( long )60*60*24*NUM_DAYS);
   
    X509_set_pubkey( certificate, evpKey );

    X509_NAME *name = X509_get_subject_name( certificate );

    /* This function creates and adds the entry, working out the
     * correct string type and performing checks on its length.
     * Normally we'd check the return value for errors...
     */
    X509_NAME_add_entry_by_txt(name,"C",
                MBSTRING_ASC, (uint8_t*)"UK", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name,"CN",
                MBSTRING_ASC, (uint8_t*)"OpenSSM", -1, -1, 0);

    /* Its self signed so set the issuer name to be the same as the
     * subject.
     */
    X509_set_issuer_name( certificate ,name);

    ////////////////////////////////
    /* Add various extensions: standard extensions */
    add_ext( certificate, NID_basic_constraints, (char*)"critical,CA:TRUE");
    add_ext( certificate, NID_key_usage, (char*)"critical,keyCertSign,cRLSign");

    add_ext( certificate, NID_subject_key_identifier, (char*)"hash");

    /* Some Netscape specific extensions */
    add_ext( certificate, NID_netscape_cert_type, (char*)"sslCA");

    add_ext( certificate, NID_netscape_comment, (char*)"example comment extension");

     // X509_gmtime_adj(X509_get_notBefore( certificate ),1);
    // ASN1_TIME_set( X509_get_notAfter( certificate ), now + 1000000 );
    // ASN1_TIME_set( X509_get_notBefore( certificate ), now);
    EnclaveSetTime( now + 1);
    // X509_gmtime_adj(X509_get_notAfter( certificate ),( long )60*60*24*NUM_DAYS);
   

    if ( ! X509_sign( certificate, evpKey, EVP_sha256() ) )
    {
        EVP_PKEY_free( evpKey );
        X509_free( certificate );
        certificate = NULL;
        return OPENSSM_UNEXPECTED;
    }

    EVP_PKEY_free( evpKey );    
    return OPENSSM_SUCCESS;
}

OpenSSMStatus HandleTransaction(  SecureMsg*      secureMsg, 
                                    uint32_t        secureMsgSize,
                                    EncryptedMsg*   encryptedMsg, 
                                    size_t          maxResponseSize )
{
    if( secureMsgSize != sizeof( SecureMsgType ) + sizeof( TransactionRequest ) )
        return OPENSSM_SECURE_MSG_BAD_SIZE;

    uint32_t responseSize = sizeof( EncryptedMsg )                  + 
                            sizeof( SecureMsgType )                 + 
                            sizeof( TransactionResponse );

    if( responseSize > maxResponseSize ){
        return OPENSSM_ENCRYPTED_MSG_FAILED_RESPONSE_BUFFER_TOO_SMALL;
    }

    TransactionRequest* transaction  = ( TransactionRequest* )secureMsg->body;
    if( ssmContext.bankRecords.find( transaction->accountHandle ) == ssmContext.bankRecords.end() )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_BAD_HANDLE );

    ssmContext.bankRecords[ transaction->accountHandle ] += transaction->transactionAmount;

    secureMsg->type                              = MK_RESPONSE(TRANSACTION);
    TransactionResponse* transactionResponse     = ( TransactionResponse* )secureMsg->body;
    transactionResponse->balanceAfterTransaction = ssmContext.bankRecords[ transaction->accountHandle ];
     
    //Encrypt reply:
    uint32_t responseSecureMsgSize = responseSize - sizeof( EncryptedMsg );

    return EncryptSecureMsg( secureMsg, responseSecureMsgSize, encryptedMsg );
}

OpenSSMStatus HandleCreateAccount(  SecureMsg*      secureMsg, 
                                    uint32_t        secureMsgSize,
                                    EncryptedMsg*   encryptedMsg, 
                                    size_t          maxResponseSize )
{
    if( secureMsgSize != sizeof( SecureMsgType ) + sizeof( CreateAccountRequest ) )
        return OPENSSM_SECURE_MSG_BAD_SIZE;

    uint32_t responseSize = sizeof( EncryptedMsg )                  + 
                            sizeof( SecureMsgType )                 + 
                            sizeof( CreateAccountResponse );

    if( responseSize > maxResponseSize ){
        return OPENSSM_ENCRYPTED_MSG_FAILED_RESPONSE_BUFFER_TOO_SMALL;
    }

    CreateAccountRequest* createAccount  = ( CreateAccountRequest* )secureMsg->body;
    double minimumAllowedBalance = createAccount->minimumAllowedBalance;

    secureMsg->type                               = MK_RESPONSE(CREATE_ACCOUNT);
    CreateAccountResponse* createAccountResponse  = ( CreateAccountResponse* )secureMsg->body;
    createAccountResponse->accountHandle          = GetRandomHandle();

    ssmContext.bankRecords[ createAccountResponse->accountHandle ] = minimumAllowedBalance;
    
    //Encrypt reply:
    uint32_t responseSecureMsgSize = responseSize - sizeof( EncryptedMsg );

    return EncryptSecureMsg( secureMsg, responseSecureMsgSize, encryptedMsg );
}

OpenSSMStatus HandleImportRSAKey( SecureMsg*      secureMsg, 
                                        uint32_t        secureMsgSize,
                                        EncryptedMsg*   encryptedMsg, 
                                        size_t          maxResponseSize )
{
    OpenSSMStatus ret = HandleImportRSAKey_verifySize( secureMsg, secureMsgSize );
    if( ret != OPENSSM_SUCCESS )
        return ret;

    ImportRSAKeyMsg* importKey  = ( ImportRSAKeyMsg* )secureMsg->body;
    
    EVP_PKEY* evpKey = NULL;
    const uint8_t* t = (const uint8_t* )importKey->privateKeyAsDER;
    EVP_PKEY* d2iRet = d2i_PrivateKey(  EVP_PKEY_RSA, 
                                        &evpKey, 
                                        &t, 
                                        importKey->privateKeySize );
    
    if( NULL == d2iRet || d2iRet != evpKey )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_BAD_KEY_ENCODING );

    return HandleImportRSAKey_storeAndreply(    evpKey,                                                    
                                                secureMsg, 
                                                encryptedMsg, 
                                                maxResponseSize );
}

OpenSSMStatus HandlePing(   SecureMsg*      secureMsg, 
                            uint32_t        secureMsgSize,
                            EncryptedMsg*   encryptedMsg, 
                            size_t          maxResponseSize )
{
    uint32_t responseSize = encryptedMsg->cipherSize + sizeof( EncryptedMsg );
    if( responseSize > maxResponseSize )
        return OPENSSM_ENCRYPTED_MSG_FAILED_RESPONSE_BUFFER_TOO_SMALL;
            
    return EncryptSecureMsg( secureMsg, encryptedMsg->cipherSize ,encryptedMsg );
}

OpenSSMStatus HandleGenerateKeyPairRSA( SecureMsg*      secureMsg, 
                                        uint32_t        secureMsgSize,
                                        EncryptedMsg*   encryptedMsg, 
                                        size_t          maxResponseSize )
{
    OpenSSMStatus ret = HandleGenerateKeyPairRSA_verifySize( secureMsg, secureMsgSize );
    if( ret != OPENSSM_SUCCESS )
        return ret;
    
    RSAGenerateKeyPairMsg* genKeyPair  = ( RSAGenerateKeyPairMsg* )secureMsg->body;
    RSA*                   keyPair     = NULL;
    X509*                  x509        = NULL;
    ret = HandleGenerateKeyPairRSA_generateKey( &keyPair, genKeyPair );
    
    if( OPENSSM_SUCCESS != ret )
         return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, ret );
    
    if( OPENSSM_SUCCESS != HandleGenerateKeyPairRSA_createX509Cert( keyPair, &x509, genKeyPair->creationTimestamp ) )
         return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_UNEXPECTED );
    
    return HandleGenerateKeyPairRSA_storeAndreply(  keyPair, 
                                                    x509,
                                                    genKeyPair->attributes, 
                                                    secureMsg, 
                                                    encryptedMsg, 
                                                    maxResponseSize );
}

// void WipeKeyMaterial( void* keyMaterial, size_t size )
// {
//     memset_s( keyMaterial, size, 0 , size );
// }

OpenSSMStatus ComputeProtectionSecret_fillProtectionSource( SharedCustodySpec   *sharedCustudySpec,
                                                            ProtectionSecret    *protectionSource ) 
{
    static const uint8_t  zeroIV[ SGX_AESGCM_IV_SIZE ] = {0};
    static const uint8_t* NO_ADD_POINTER               = NULL;
    static const uint32_t NO_ADD_SIZE                  = 0;
    
    for( int participantIdx = 0; participantIdx < sharedCustudySpec->numParticipants; ++participantIdx )
    { 
        sgx_sha256_hash_t *userID = 
            ( sgx_sha256_hash_t* )sharedCustudySpec->protectionTokens[ participantIdx ].userID.userID;
        int userIdx = LocateSharedKeys( userID );
        if( userIdx < 0 )
            return OPENSSM_SECURE_MSG_UNEXPECTED_ERROR;
        
        Nonce &userNonce = sharedCustudySpec->protectionTokens[ participantIdx ].userNonce;
        uint8_t context[ sizeof( Nonce ) * 2 ];
        memcpy( context,                   ssmContext.currentChallenge, sizeof( Nonce ) );
        memcpy( context + sizeof( Nonce ), userNonce,                   sizeof( Nonce ) );
        
        sgx_aes_gcm_128bit_key_t*   userMKKey   = &ssmContext.usersSharedKeys[ userIdx ].mk;
        const uint16_t              LABEL_TK    = 0x4B54; //Label Token Key: "TK"
        sgx_aes_gcm_128bit_key_t    tokenKey    = {0};
        if( OPENSSM_SUCCESS != DeriveKey_AES_CMAC(  userMKKey, 
                                                    LABEL_TK, 
                                                    context,
                                                    sizeof( context ),
                                                    &tokenKey ) )
            return OPENSSM_SECURE_MSG_UNEXPECTED_ERROR;
        
        sgx_status_t ret = sgx_rijndael128GCM_decrypt(  &tokenKey,
                                                        sharedCustudySpec->protectionTokens[ participantIdx ].protectionSecret,
                                                        sizeof( ProtectionSecret ),
                                                        ( uint8_t* )&protectionSource[ participantIdx ],
                                                        zeroIV,
                                                        sizeof( zeroIV ),
                                                        NO_ADD_POINTER,
                                                        NO_ADD_SIZE,
                                                        &sharedCustudySpec->protectionTokens[ participantIdx ].mac );
        if( SGX_SUCCESS != ret ) 
            return OPENSSM_SECURE_MSG_MAC_MISMATCH;
    }

    if( OPENSSM_SUCCESS != ssmContext.RefreshSSMChallenge() )
        return OPENSSM_SECURE_MSG_UNEXPECTED_ERROR;

    return OPENSSM_SUCCESS;
}

OpenSSMStatus ComputeProtectionSecret( SharedCustodySpec            *sharedCustudySpec, 
                                        sgx_aes_gcm_128bit_key_t    *masterProtectionSecret  )
{
    const uint16_t      LABEL_GK       = 0x4B47; //Label Generate Key: "GK" (Note little endianess)

    ProtectionSecret protectionSource[ sharedCustudySpec->numParticipants ];
    
    if( OPENSSM_SUCCESS != ComputeProtectionSecret_fillProtectionSource( sharedCustudySpec, protectionSource ) )
        return OPENSSM_SECURE_MSG_UNEXPECTED_ERROR;
    
    SharedKeys *securityOfficerKeys = &ssmContext.usersSharedKeys[ 0 ];
    if( OPENSSM_SUCCESS != DeriveKey_AES_CMAC(  &securityOfficerKeys->mk, 
                                                LABEL_GK, 
                                                ( uint8_t* ) &protectionSource[0],
                                                sizeof( ProtectionSecret ) * sharedCustudySpec->numParticipants,
                                                masterProtectionSecret ) )
        return OPENSSM_SECURE_MSG_UNEXPECTED_ERROR;
    
    return OPENSSM_SUCCESS;
}

OpenSSMStatus LoadKeyFromDisk(  KeyObjectType               &keyType, 
                                KeyAttributes               &attributes,
                                uint64_t                    keyHandle, 
                                uint8_t*                    keyMaterial, 
                                uint32_t                    &keyMaterialSize,    
                                sgx_aes_gcm_128bit_key_t    *masterProtectionSecret )
{
    const uint32_t  MAX_SEALED_KEY_SIZE                         = 4096;
    static uint8_t  sealedKey[ MAX_SEALED_KEY_SIZE ]            = {0};
    static uint8_t  serializedKeyBuffer[ MAX_SEALED_KEY_SIZE ]  = {0};
    const uint8_t   zeroIV[ SGX_AESGCM_IV_SIZE ]                = {0};
    const uint8_t*  NO_ADD_POINTER                              = NULL;
    const uint32_t  NO_ADD_SIZE                                 = 0;

    uint32_t        sealedKeySize            
                       = 0;
    uint32_t        aadSize                                     = 0;
    uint8_t*        aad                                         = NULL;
    
    if( SGX_SUCCESS != ocall_read_key_from_disk( &sealedKeySize, keyHandle, sealedKey, MAX_SEALED_KEY_SIZE ) ||
        sealedKeySize == 0 || 
        sealedKeySize > MAX_SEALED_KEY_SIZE ) 
        return OPENSSM_SECURE_FAILED_READING_KEY_FROM_FILE;
    
    // Unseal data
    uint32_t        expectedUnsealedSize    = sealedKeySize - sizeof( sgx_sealed_data_t );
    uint32_t        actualUnsealedDataSize  = sealedKeySize;
    sgx_status_t    err                     = SGX_ERROR_UNEXPECTED;
    err = sgx_unseal_data( ( sgx_sealed_data_t* )sealedKey,
                            aad,
                            &aadSize,
                            (uint8_t*)serializedKeyBuffer,
                            &actualUnsealedDataSize );
    if( SGX_SUCCESS != err )
        return OPENSSM_SECURE_FAILED_UNSEALING_KEY_FROM_FILE;
    if( expectedUnsealedSize != actualUnsealedDataSize || aadSize != 0 )
        return OPENSSM_SECURE_FAILED_UNSEALING_KEY_FROM_FILE;
    
    //Parse SerializedKeyObject
    SerializedKeyObject *serializedKeyObject = ( SerializedKeyObject* )serializedKeyBuffer;
    if( keyMaterialSize < actualUnsealedDataSize - sizeof( SerializedKeyObject ) )
        return OPENSSM_SECURE_FAILED_UNSEALING_KEY_FROM_FILE;
    
    keyMaterialSize = actualUnsealedDataSize - sizeof( SerializedKeyObject );
    keyType         = serializedKeyObject->type;
    attributes      = serializedKeyObject->attributes;

    //Decrypt key material
    sgx_status_t ret = sgx_rijndael128GCM_decrypt(  masterProtectionSecret,
                                                    serializedKeyObject->encryptedKeyMaterial,
                                                    keyMaterialSize,
                                                    keyMaterial,
                                                    zeroIV,
                                                    sizeof( zeroIV),
                                                    NO_ADD_POINTER,
                                                    NO_ADD_SIZE,
                                                    &serializedKeyObject->mac );
    if( SGX_ERROR_MAC_MISMATCH == ret ) 
        return OPENSSM_SECURE_MSG_MAC_MISMATCH;
    if( SGX_SUCCESS != ret )
        return OPENSSM_SECURE_FAILED_UNSEALING_KEY_FROM_FILE;
    
    return OPENSSM_SUCCESS;
}

OpenSSMStatus StoreKeyToDisk(   KeyObjectType   keyType, 
                                KeyAttributes   attributes,
                                uint64_t        keyHandle, 
                                uint8_t*        keyMaterial, 
                                size_t          keyMaterialSize,    
                                sgx_aes_gcm_128bit_key_t *masterProtectionSecret )
{
    const        uint8_t* NO_ADD_POINTER               = NULL;
    const        uint32_t NO_ADD_SIZE                  = 0;
    static const uint8_t  zeroIV[ SGX_AESGCM_IV_SIZE ] = {0};

    //----------------------------Serialize key:
    uint32_t            serializedDataSize   = sizeof( SerializedKeyObject ) + keyMaterialSize;
    SerializedKeyObject *serializedKeyObject = ( SerializedKeyObject* )malloc( serializedDataSize );
    if( NULL == serializedKeyObject )
        return OPENSSM_SECURE_MSG_UNEXPECTED_ERROR;

    serializedKeyObject->type       = keyType;
    serializedKeyObject->attributes = attributes;
    serializedKeyObject->handle     = keyHandle;

    //---------------------Encrypt key
    if( SGX_SUCCESS != sgx_rijndael128GCM_encrypt(  masterProtectionSecret,
                                                    keyMaterial,
                                                    keyMaterialSize,
                                                    serializedKeyObject->encryptedKeyMaterial,
                                                    zeroIV, //masterProtectionSecret is different every time, hence zeroIV is OK
                                                    SGX_AESGCM_IV_SIZE,
                                                    NO_ADD_POINTER,
                                                    NO_ADD_SIZE,
                                                    &serializedKeyObject->mac ) )
    {
        free( serializedKeyObject );
        return OPENSSM_SECURE_MSG_UNEXPECTED_ERROR;
    }
    /////////////------------- Sealing data
    //Seal encrypted serialized key:
    uint32_t sealedDataSize = serializedDataSize + sizeof(sgx_sealed_data_t);
    uint8_t* sealedKey      = ( uint8_t* )calloc( 1, sealedDataSize );
    if( NULL == sealedKey ){
        free( serializedKeyObject );
        return OPENSSM_SECURE_MSG_UNEXPECTED_ERROR;
    }

    //Seal data:
    sgx_attributes_t attribute_mask;
    attribute_mask.flags    = SGX_FLAGS_RESERVED | SGX_FLAGS_INITTED | SGX_FLAGS_DEBUG;
    attribute_mask.xfrm     = 0x0;
    sgx_status_t err        = SGX_ERROR_UNEXPECTED;
    err = sgx_seal_data_ex( SGX_KEYPOLICY_MRENCLAVE, 
                            attribute_mask, 
                            TSEAL_DEFAULT_MISCMASK, 
                            NO_ADD_SIZE,
                            NO_ADD_POINTER, 
                            serializedDataSize, 
                            ( uint8_t* )serializedKeyObject,
                            sealedDataSize, 
                            ( sgx_sealed_data_t* )sealedKey );

    if( SGX_SUCCESS != err ){
        free( sealedKey );
        free( serializedKeyObject );
        return OPENSSM_SECURE_MSG_UNEXPECTED_ERROR;
    }

    free( serializedKeyObject );

    //Write sealed data to file:
    uint32_t retVal = OPENSSM_SUCCESS;
    if( SGX_SUCCESS     != ocall_store_key_on_disk( &retVal, keyHandle, sealedKey, sealedDataSize ) ||
        OPENSSM_SUCCESS != retVal ) {
        free( sealedKey );
        return OPENSSM_SECURE_MSG_UNEXPECTED_ERROR;
    }

    free( sealedKey );

    return OPENSSM_SUCCESS;
}

OpenSSMStatus HandleGenerateKeyPairECDSA_OpenSSL(   SecureMsg*      secureMsg, 
                                                    uint32_t        secureMsgSize,
                                                    EncryptedMsg*   encryptedMsg, 
                                                    size_t          maxResponseSize )
{
    OpenSSMStatus ret = HandleGenerateKeyPairECDSA_OpenSSL_verifySize( secureMsg, secureMsgSize );
    if( ret != OPENSSM_SUCCESS )
        return ret;

    EC_KEY* keyPair = NULL;
    ECDSA_GenerateKeyPairOpenSSLMsg* genKeyPair  = ( ECDSA_GenerateKeyPairOpenSSLMsg* )secureMsg->body;

    ret = HandleGenerateKeyPairECDSA_OpenSSL_generateKey( &keyPair, genKeyPair );

    if( OPENSSM_SUCCESS != ret )
         return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, ret );
    
    return HandleGenerateKeyPairECDSA_OpenSSL_storeAndreply(    keyPair, 
                                                                genKeyPair->attributes, 
                                                                secureMsg, 
                                                                encryptedMsg, 
                                                                maxResponseSize );
}

OpenSSMStatus HandleGenerateKeyPairECDSA( SecureMsg*      secureMsg, 
                                          uint32_t        secureMsgSize,
                                          EncryptedMsg*   encryptedMsg, 
                                          size_t          maxResponseSize )
{
    OpenSSMStatus ret = HandleGenerateKeyPairECDSA_verifySize( secureMsg, secureMsgSize );
    if( ret != OPENSSM_SUCCESS )
        return ret;

    ECDSA_GenerateKeyPairMsg* genKeyPair   = ( ECDSA_GenerateKeyPairMsg* )secureMsg->body;
    sgx_ec256_public_t       publicKey     = {0};
    sgx_ec256_private_t      *privateKey   = ( sgx_ec256_private_t* )malloc( sizeof( sgx_ec256_private_t ) );
    if( NULL == privateKey )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_UNEXPECTED_ERROR );

    ret = HandleGenerateKeyPairECDSA_generateKey( privateKey, &publicKey );
    if( OPENSSM_SUCCESS != ret ) {
        free( privateKey );
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, ret );
    }
    
    uint64_t keyHandle = HandleGenerateKeyPairECDSA_computeHandle( &publicKey );  
    
    if( true == genKeyPair->attributes.storeOnDisk ) {
        // HandleGenerateKeyPairECDSA_storeOnDisk( secureMsg, genKeyPair );
        SharedCustodySpec* sharedCustudySpec = (SharedCustodySpec*)  ( (uint8_t*)secureMsg + 
                                                                        sizeof( SecureMsgType ) + 
                                                                        sizeof( ECDSA_GenerateKeyPairMsg ) );

        // if( OPENSSM_SUCCESS != VerifyAuthorization( genKeyPair, sharedCustudySpec ) )
        //     return OPENSSM_SECURE_MSG_UNEXPECTED_ERROR;
        
        sgx_aes_gcm_128bit_key_t masterProtectionSecret = {0};
        if( OPENSSM_SUCCESS != ComputeProtectionSecret( sharedCustudySpec, &masterProtectionSecret ) ) {
            free( privateKey );
            return OPENSSM_SECURE_MSG_UNEXPECTED_ERROR;
        }
        
        // sgx_cmac_128bit_tag_t keyGenerationProofs[ sharedCustudySpec->numParticipants ];

        if( OPENSSM_SUCCESS != StoreKeyToDisk(  ECDSA_KEY, 
                                                genKeyPair->attributes, 
                                                keyHandle, 
                                                ( uint8_t* )privateKey, 
                                                sizeof( sgx_ec256_private_t ),
                                                &masterProtectionSecret )       ){

            free( privateKey );
            return OPENSSM_SECURE_MSG_UNEXPECTED_ERROR;                                                             
        }
        
    }
    else {
        ret = StoreKeyInLiveStorage(    ECDSA_KEY, 
                                        genKeyPair->attributes, 
                                        keyHandle, 
                                        privateKey );
        if( OPENSSM_SUCCESS != ret ) {
            free( privateKey );
            return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, ret );
        }
    }
    
    return  HandleGenerateKeyPairECDSA_reply(   &publicKey,
                                                keyHandle,
                                                secureMsg, 
                                                encryptedMsg, 
                                                maxResponseSize );
}

void* DeserializeKey( KeyObjectType keyType, uint8_t* keyMaterial, uint32_t keyMaterialSize )
{
    void* key = NULL;
    switch( keyType ){
        case ECDSA_KEY:
            if( keyMaterialSize != sizeof( sgx_ec256_private_t ) )
                return NULL;

            key = malloc( sizeof( sgx_ec256_private_t ) );
            if( NULL == key )
                return NULL;

            memcpy( key, keyMaterial, keyMaterialSize );
            return key;
        break;

        default:
            return NULL;
    }
}


OpenSSMStatus HandleGetConfigID         ( SecureMsg*      secureMsg, 
                                          uint32_t        secureMsgSize,
                                          EncryptedMsg*   encryptedMsg, 
                                          size_t          maxResponseSize )
{
    if( secureMsgSize != sizeof( SecureMsgType ) )
        return OPENSSM_ENCRYPTED_MSG_FAILED_BAD_MSG;

    secureMsg->type = MK_RESPONSE(GET_CONFIG_ID);
   
    //Ensure we have room to reply:
    uint32_t responseSize = sizeof( EncryptedMsg ) + 
                            sizeof( SecureMsgType ) +
                            sizeof( GET_CONFIG_ID_ResponseMsg );   
    if( responseSize > maxResponseSize ){
        return OPENSSM_ENCRYPTED_MSG_FAILED_RESPONSE_BUFFER_TOO_SMALL;
    }                         
    
    memcpy( secureMsg->body, ssmContext.allowedUsersTag, sizeof( ssmContext.allowedUsersTag ) );
    //Encrypt reply:
    uint32_t secureReplyMsgSize = responseSize - sizeof( EncryptedMsg );
    return EncryptSecureMsg( secureMsg, secureReplyMsgSize, encryptedMsg );
}

OpenSSMStatus HandleGetChallenge        ( SecureMsg*      secureMsg, 
                                          uint32_t        secureMsgSize,
                                          EncryptedMsg*   encryptedMsg, 
                                          size_t          maxResponseSize )
{
    if( secureMsgSize != sizeof( SecureMsgType ) )
        return OPENSSM_ENCRYPTED_MSG_FAILED_BAD_MSG;

    secureMsg->type = MK_RESPONSE(GET_CHALLENGE);
   
    //Ensure we have room to reply:
    uint32_t responseSize = sizeof( EncryptedMsg ) + 
                            sizeof( SecureMsgType ) +
                            sizeof( GetChallengeResponse );   
    if( responseSize > maxResponseSize ){
        return OPENSSM_ENCRYPTED_MSG_FAILED_RESPONSE_BUFFER_TOO_SMALL;
    }                         
    
    memcpy( secureMsg->body, ssmContext.currentChallenge, sizeof( ssmContext.currentChallenge ) );
    //Encrypt reply:
    uint32_t secureReplyMsgSize = responseSize - sizeof( EncryptedMsg );
    return EncryptSecureMsg( secureMsg, secureReplyMsgSize, encryptedMsg );
}

OpenSSMStatus HandleArmKey              ( SecureMsg*      secureMsg, 
                                          uint32_t        secureMsgSize,
                                          EncryptedMsg*   encryptedMsg, 
                                          size_t          maxResponseSize )
{
    OpenSSMStatus ret = HandleArmKey_verifySize( secureMsg, secureMsgSize );
    if( ret != OPENSSM_SUCCESS )
        return ret;

    ArmKeyRequest* armKeyRequest   = ( ArmKeyRequest* )secureMsg->body;
       
    sgx_aes_gcm_128bit_key_t masterProtectionSecret = {0};
    if( OPENSSM_SUCCESS != ComputeProtectionSecret( &armKeyRequest->sharedCustodySpec, 
                                                    &masterProtectionSecret ) )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_SHARED_CUSTUDY_ERROR );                                                             
        
    KeyObjectType               keyType; 
    KeyAttributes               attributes;
    uint8_t                     keyMaterial[ MAX_SERILIZED_KEY_SIZE ]; 
    uint32_t                    keyMaterialSize = MAX_SERILIZED_KEY_SIZE;
    
    ret = LoadKeyFromDisk( keyType,
                            attributes,
                            armKeyRequest->keyHandle, 
                            keyMaterial,
                            keyMaterialSize,
                            &masterProtectionSecret );
    if( OPENSSM_SUCCESS != ret)
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, ret );                                                             

    void* key = DeserializeKey( keyType, keyMaterial, keyMaterialSize );
    if( NULL == key )
        return OPENSSM_SECURE_MSG_UNEXPECTED_ERROR;
    //TODO: wipe key from keyMaterial

    ret = StoreKeyInLiveStorage(    keyType, 
                                    attributes, 
                                    armKeyRequest->keyHandle, 
                                    key );
    if( OPENSSM_SUCCESS != ret ) 
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, ret );     

    return  ReplyWithoutPayload(    MK_RESPONSE(ARM_KEY),
                                    secureMsg, 
                                    encryptedMsg, 
                                    maxResponseSize );
}

OpenSSMStatus HandleGenerateKeyAES_GCM( SecureMsg*      secureMsg, 
                                          uint32_t        secureMsgSize,
                                          EncryptedMsg*   encryptedMsg, 
                                          size_t          maxResponseSize )
{
    OpenSSMStatus ret = HandleGenerateKeyAES_GCM_verifySize( secureMsg, secureMsgSize );
    if( ret != OPENSSM_SUCCESS )
        return ret;
    
    AES_GCM_GenerateKeyMsg* genKey   = ( AES_GCM_GenerateKeyMsg* )secureMsg->body;
    if( genKey->keySizeInBits != 128 && genKey->keySizeInBits != 192 && genKey->keySizeInBits != 256 )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_BAD_KEY_SIZE );

    AES_KEY aesKey = {0};
    if( SGX_SUCCESS != sgx_read_rand( aesKey, genKey->keySizeInBits / 8 ) )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_UNEXPECTED_ERROR );

    return  HandleGenerateKeyAES_GCM_storeAndreply(     &aesKey, 
                                                        genKey->keySizeInBits,
                                                        genKey->attributes, 
                                                        secureMsg, 
                                                        encryptedMsg, 
                                                        maxResponseSize );
}

OpenSSMStatus HandleSignRSA_verifySize( SecureMsg* secureMsg, uint32_t secureMsgSize )
{
    if( secureMsgSize < sizeof( SecureMsgType ) + sizeof( RSASignMsg ) )
        return OPENSSM_SECURE_MSG_BAD_SIZE;

    RSASignMsg* signRSAMsg      = ( RSASignMsg* )secureMsg->body;
    uint32_t expectedTotalSize  =   sizeof( SecureMsgType )  + 
                                    sizeof( RSASignMsg )     + 
                                    signRSAMsg->dataSize;

    if( expectedTotalSize != secureMsgSize )
        return OPENSSM_SECURE_MSG_BAD_SIZE;

    return OPENSSM_SUCCESS;
}

OpenSSMStatus HandleSignECDSA_verifySize( SecureMsg* secureMsg, uint32_t secureMsgSize )
{
    if( secureMsgSize < sizeof( SecureMsgType ) + sizeof( ECDSASignMsg ) )
        return OPENSSM_SECURE_MSG_BAD_SIZE;

    ECDSASignMsg* signRSAMsg      = ( ECDSASignMsg* )secureMsg->body;
    uint32_t expectedTotalSize  =   sizeof( SecureMsgType )  + 
                                    sizeof( ECDSASignMsg )   + 
                                    signRSAMsg->dataSize;

    if( expectedTotalSize != secureMsgSize )
        return OPENSSM_SECURE_MSG_BAD_SIZE;

    return OPENSSM_SUCCESS;
}

OpenSSMStatus HandleAES_GCM_Encrypt_verifySize( SecureMsg* secureMsg, uint32_t secureMsgSize )
{
    if( secureMsgSize < sizeof( SecureMsgType ) + sizeof( AES_GCM_EncryptMsg ) )
        return OPENSSM_SECURE_MSG_BAD_SIZE;

    AES_GCM_EncryptMsg* encryptMsg  = ( AES_GCM_EncryptMsg* )secureMsg->body;
    uint32_t expectedTotalSize      =   sizeof( SecureMsgType )  + 
                                        sizeof( AES_GCM_EncryptMsg )   + 
                                        encryptMsg->dataSize;

    if( expectedTotalSize != secureMsgSize )
        return OPENSSM_SECURE_MSG_BAD_SIZE;

    return OPENSSM_SUCCESS;
}

OpenSSMStatus HandleAES_GCM_Decrypt_verifySize( SecureMsg* secureMsg, uint32_t secureMsgSize )
{
    if( secureMsgSize < sizeof( SecureMsgType ) + sizeof( AES_GCM_DecryptMsg ) )
        return OPENSSM_SECURE_MSG_BAD_SIZE;

    AES_GCM_DecryptMsg* decryptMsg  = ( AES_GCM_DecryptMsg* )secureMsg->body;
    uint32_t expectedTotalSize      =   sizeof( SecureMsgType )  + 
                                        sizeof( AES_GCM_DecryptMsg )   + 
                                        decryptMsg->cipherSize;

    if( expectedTotalSize != secureMsgSize )
        return OPENSSM_SECURE_MSG_BAD_SIZE;

    return OPENSSM_SUCCESS;
}

void SanityECVerify( uint8_t* data,
                     uint32_t dataSize,
                     uint8_t* signature, 
                     uint32_t signatureSize, 
                     EVP_PKEY* ecKey )
{

    uint8_t* serilizedPublicKey = NULL;
    int      publicKeySize      = i2d_PUBKEY( ecKey, &serilizedPublicKey );
    printf("########### %s: %d; publicKeySize = %d\n", __FUNCTION__, __LINE__, publicKeySize );    
    if( publicKeySize <= 0 )
         return;

    EVP_PKEY* ecKeyCopy = NULL;
    ecKeyCopy = d2i_PUBKEY(  &ecKeyCopy ,(const unsigned char**)&serilizedPublicKey, publicKeySize );
    printf("########### %s: %d; ecKeyCopy %p \n", __FUNCTION__, __LINE__, ecKeyCopy );    

    EVP_MD_CTX *ctx             = EVP_MD_CTX_create();
    const EVP_MD* digestMechanism     = EVP_sha256();

    EVP_DigestInit( ctx, digestMechanism );
    // EVP_DigestVerifyInit( ctx, NULL, digestMechanism, NULL, ecKey );
    EVP_DigestVerifyInit( ctx, NULL, digestMechanism, NULL, ecKeyCopy );

    EVP_DigestVerifyUpdate( ctx, data, dataSize );
    int ret = EVP_DigestVerifyFinal( ctx, signature, signatureSize );

    printf("########### %s: %d; EVP_DigestVerifyFinal returned %d \n", __FUNCTION__, __LINE__, ret );
}


OpenSSMStatus HandleSignECDSAOpenSSL_sign(   SecureMsg*      secureMsg, 
                                    // EVP_PKEY*       rsaKey,
                                    DrawerManager*  drawerManager,
                                    EncryptedMsg*   encryptedMsg, 
                                    size_t          maxResponseSize )
{
    const int      SUCCESS                  = 1;

    EVP_PKEY* ecKey = (EVP_PKEY*)drawerManager->GetAvailableItem();
    if( NULL == ecKey ) {
        printf("########### %s: %d; ecKey is NULL\n", __FUNCTION__, __LINE__ );
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_UNEXPECTED_ERROR ); 
    }

    int maxSignatureSize = EVP_PKEY_size( ecKey );
    if( maxSignatureSize <= 0 )
        return OPENSSM_SECURE_MSG_UNEXPECTED_ERROR;

    uint8_t                     signature[ maxSignatureSize ];
    ECDSASignOpenSSLMsg*        signRequest                      = ( ECDSASignOpenSSLMsg* )secureMsg->body;
    bool                        signSuccessfull                  = false;
    EVP_MD_CTX*                 ctx                              = NULL;
    uint32_t                    signatureSize                    = 0;
    do
    {
        ctx = EVP_MD_CTX_create();
        if(ctx == NULL) 
            break;
        const EVP_MD* digestMechanism = EVP_sha256();
        if( digestMechanism == NULL ) 
            break;
        
        if( SUCCESS != EVP_SignInit_ex( ctx, digestMechanism, NULL) ) 
            break;
        
        if( SUCCESS != EVP_SignUpdate( ctx, signRequest->data, signRequest->dataSize ) )
            break;
        
        if( SUCCESS != EVP_SignFinal( ctx, signature, &signatureSize, ecKey ) ) 
            break;

        signSuccessfull = true;
    } while(0);
    
    if(ctx) {
        EVP_MD_CTX_destroy(ctx);
        ctx = NULL;
    }

    // RSA_free(dup_rsa); // Decrement reference count
    drawerManager->ReturnItem( ecKey );

    if( ! signSuccessfull )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_UNEXPECTED_ERROR );

    uint32_t signResponseSize = sizeof( SecureMsgType )                + 
                                sizeof( ECDSAOpenSSL_SignResponseMsg ) + 
                                signatureSize;
    if( maxResponseSize < signResponseSize )
        return OPENSSM_ENCRYPTED_MSG_FAILED_RESPONSE_BUFFER_TOO_SMALL;

    secureMsg->type                            = MK_RESPONSE( ECDSA_SIGN_OPENSSL );

    ECDSAOpenSSL_SignResponseMsg* signResponse = ( ECDSAOpenSSL_SignResponseMsg* )secureMsg->body;
    signResponse->signatureSize                = signatureSize;

    memcpy( signResponse->signature, signature, signatureSize );
    
    return EncryptSecureMsg( secureMsg, signResponseSize, encryptedMsg );;
}


OpenSSMStatus HandleSignRSA_sign(   SecureMsg*      secureMsg, 
                                    // EVP_PKEY*       rsaKey,
                                    DrawerManager*  drawerManager,
                                    EncryptedMsg*   encryptedMsg, 
                                    size_t          maxResponseSize )
{
    const int      SUCCESS                  = 1;
    // const uint32_t MAX_SIGNATURE_SIZE       = 1024;

    // RSA *rsa = EVP_PKEY_get1_RSA(rsaKey); // Get the underlying RSA key
    // RSA *dup_rsa = RSAPrivateKey_dup(rsa); // Duplicate the RSA key

    // EVP_PKEY *rsaKeyCopy = CreateEVPKey( dup_rsa );
    // EVP_PKEY* rsaKey = (EVP_PKEY*)drawerManager->drawers[ 0 ];
    EVP_PKEY* rsaKey = (EVP_PKEY*)drawerManager->GetAvailableItem();
    if( NULL == rsaKey ) {
        printf("########### %s: %d; rsaKey is NULL\n", __FUNCTION__, __LINE__ );
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_UNEXPECTED_ERROR ); 
    }

    int maxSignatureSize = EVP_PKEY_size( rsaKey );
    if( maxSignatureSize <= 0 )
        return OPENSSM_SECURE_MSG_UNEXPECTED_ERROR;

    uint8_t         signature[ maxSignatureSize ];
    RSASignMsg*     signRequest                      = ( RSASignMsg* )secureMsg->body;
    bool            signSuccessfull                  = false;
    EVP_MD_CTX*     ctx                              = NULL;
    uint32_t        signatureSize                    = 0;
    do
    {
        ctx = EVP_MD_CTX_create();
        if(ctx == NULL) 
            break;
        const EVP_MD* digestMechanism = EVP_sha256();
        if( digestMechanism == NULL ) 
            break;
        
        if( SUCCESS != EVP_SignInit_ex( ctx, digestMechanism, NULL) ) 
            break;
        
        if( SUCCESS != EVP_SignUpdate( ctx, signRequest->data, signRequest->dataSize ) )
            break;
        
        if( SUCCESS != EVP_SignFinal( ctx, signature, &signatureSize, rsaKey ) ) 
            break;

        signSuccessfull = true;
    } while(0);
    
    if(ctx) {
        EVP_MD_CTX_destroy(ctx);
        ctx = NULL;
    }

    // RSA_free(dup_rsa); // Decrement reference count
    drawerManager->ReturnItem( rsaKey );

    if( ! signSuccessfull )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_UNEXPECTED_ERROR );

    uint32_t signResponseSize = sizeof( SecureMsgType )      + 
                                sizeof( RSASignResponseMsg ) + 
                                signatureSize;
    if( maxResponseSize < signResponseSize )
        return OPENSSM_ENCRYPTED_MSG_FAILED_RESPONSE_BUFFER_TOO_SMALL;

    secureMsg->type                  = MK_RESPONSE( RSA_SIGN );

    RSASignResponseMsg* signResponse = ( RSASignResponseMsg* )secureMsg->body;
    signResponse->signatureSize      = signatureSize;

    memcpy( signResponse->signature, signature, signatureSize );
    
    return EncryptSecureMsg( secureMsg, signResponseSize, encryptedMsg );;
}


OpenSSMStatus HandleSignECDSA_reply(    SecureMsg               *secureMsg, 
                                        sgx_ec256_signature_t   *signature,
                                        EncryptedMsg*           encryptedMsg, 
                                        size_t                  maxResponseSize )
{
    uint32_t signResponseSize = sizeof( SecureMsgType )      + 
                                sizeof( ECDSASignResponseMsg );
                                
    if( maxResponseSize < signResponseSize )
        return OPENSSM_ENCRYPTED_MSG_FAILED_RESPONSE_BUFFER_TOO_SMALL;

    secureMsg->type                    = MK_RESPONSE(ECDSA_SIGN);
    ECDSASignResponseMsg* signResponse = ( ECDSASignResponseMsg* )secureMsg->body;

    memcpy( &signResponse->signature, signature, sizeof( sgx_ec256_signature_t ) );
    
    return EncryptSecureMsg( secureMsg, signResponseSize, encryptedMsg );
}

OpenSSMStatus HandleSignECDSA_sign(     uint8_t                 *data,
                                        uint32_t                dataSize, 
                                        sgx_ec256_private_t     *privateKey,
                                        sgx_ec256_signature_t   *signature )
{
    sgx_ecc_state_handle_t          context             = NULL;
      
    if( SGX_SUCCESS !=  sgx_ecc256_open_context( &context) || NULL == context )
        return OPENSSM_SECURE_MSG_UNEXPECTED_ERROR;

    if( SGX_SUCCESS !=  sgx_ecdsa_sign( data, 
                                        dataSize,
                                        privateKey,
                                        signature,
                                        context ) ) {
        sgx_ecc256_close_context( context );
        return OPENSSM_SECURE_MSG_UNEXPECTED_ERROR;    
    }
 
    if( SGX_SUCCESS !=  sgx_ecc256_close_context( context ) )
        return OPENSSM_SECURE_MSG_UNEXPECTED_ERROR;
 
    return OPENSSM_SUCCESS;
}


OpenSSMStatus HandleAES_CMAC_doCMAC(    SecureMsg*              secureMsg, 
                                        AES_GCM_128_Context*    aesGCMContext,
                                        EncryptedMsg*           encryptedMsg, 
                                        size_t                  maxResponseSize )
{
    sgx_cmac_128bit_tag_t mac;
    AES_GCM_EncryptMsg*   cmacRequest       = ( AES_CMAC_Msg* )secureMsg->body;
    uint32_t              cmacResponseSize  =   sizeof( SecureMsgType )    + 
                                                sizeof( AES_CMAC_ResponseMsg );

    if( maxResponseSize < cmacResponseSize )
        return OPENSSM_ENCRYPTED_MSG_FAILED_RESPONSE_BUFFER_TOO_SMALL;

    if( SGX_SUCCESS != sgx_rijndael128_cmac_msg( (sgx_aes_gcm_128bit_key_t*)&aesGCMContext->key,
                                                cmacRequest->data,
                                                cmacRequest->dataSize,
                                                &mac ) )
         return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_UNEXPECTED_ERROR );
    

    secureMsg->type                    = MK_RESPONSE(AES_CMAC);
    AES_CMAC_ResponseMsg* cmacResponse = ( AES_CMAC_ResponseMsg* )secureMsg->body;
    memcpy( &cmacResponse->mac, &mac, sizeof( mac ) );
    
    return EncryptSecureMsg( secureMsg, cmacResponseSize, encryptedMsg );
}


OpenSSMStatus LibreSSL_AESGCM_Encrypt(      const uint8_t   *key,
                                            const uint16_t  keySizeBytes,
                                            const uint8_t   *plaintext,
                                            uint32_t        plaintext_len,
                                            uint8_t         *ciphertext,
                                            const uint8_t   *iv,
                                            uint32_t        iv_len,
                                            // const uint8_t   *aad,
                                            // uint32_t        aad_len,
                                            uint8_t         *tag)
{
    EVP_CIPHER_CTX *ctx;
    // printf("-------------------------------keySizeBytes = %ld\n", keySizeBytes );
    
    int len = 0;
    // printf("-----------------------plaintext = %lx %lx %lx %lx; len =%d\n", plaintext[ 0 ], plaintext [ 1 ], plaintext[ 2], plaintext[ 3], len  );
    int ciphertext_len;

    // printf("#########3 %s: %d\n",__FUNCTION__, __LINE__ );
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) return OPENSSM_UNEXPECTED;
    // printf("#########3 %s: %d\n",__FUNCTION__, __LINE__ );
    /* Initialise the encryption operation. */

    int res;
    if( AES_KEY_128 == keySizeBytes * 8 )
        res = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    else if( AES_KEY_192 == keySizeBytes * 8 )
        res = EVP_EncryptInit_ex(ctx, EVP_aes_192_gcm(), NULL, NULL, NULL);
    else if( AES_KEY_256 == keySizeBytes * 8 ) 
        res = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    else
        return OPENSSM_UNEXPECTED;

    if(1 != res )
        return OPENSSM_UNEXPECTED;
    // printf("#########3 %s: %d\n",__FUNCTION__, __LINE__ );
    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        return OPENSSM_UNEXPECTED;
    // printf("#########3 %s: %d\n",__FUNCTION__, __LINE__ );
    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) 
        return OPENSSM_UNEXPECTED;

    // printf("#########3 %s: %d\n",__FUNCTION__, __LINE__ );
    /* Provide any AAD data. This can be called zero or more times as
     * required
     */ 
    // if(1 != EVP_EncryptUpdate(ctx, NULL, &len, NULL, 0))
    //     return OPENSSM_UNEXPECTED;
    // printf("#########3 %s: %d\n",__FUNCTION__, __LINE__ );
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        {   
            printf("ciphertext = %p; len = %d, plaintext = %p, plaintext_len = %d \n", ciphertext, &len, plaintext, plaintext_len );
            return OPENSSM_UNEXPECTED;}
    ciphertext_len = len;
    // printf("#########3 %s: %d\n",__FUNCTION__, __LINE__ );
    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) 
        return OPENSSM_UNEXPECTED;
    // printf("#########3 %s: %d\n",__FUNCTION__, __LINE__ );
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        return OPENSSM_UNEXPECTED;
    // printf("-----------------------ciphertext = %lx %lx %lx %lx; len =%d\n", ciphertext[ 0 ], ciphertext [ 1 ], ciphertext[ 2], ciphertext[ 3], ciphertext_len  );
    // printf("#########3 %s: %d\n",__FUNCTION__, __LINE__ );
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    // printf("#########3 %s: %d\n",__FUNCTION__, __LINE__ );
    return OPENSSM_SUCCESS;
}

OpenSSMStatus LibreSSL_AESGCM_Decrypt(  const uint8_t   *key,
                                        const uint16_t  keySizeBytes,
                                        //EVP_CIPHER_CTX *decryptCtx
                                        const uint8_t   *ciphertext,
                                        uint32_t        ciphertext_len,
                                        uint8_t         *plaintext,
                                        const uint8_t   *iv,
                                        uint32_t        iv_len,
                                        // const uint8_t   *aad,
                                        // uint32_t        aad_len,
                                        uint8_t         *tag )
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) return OPENSSM_UNEXPECTED;

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        return OPENSSM_UNEXPECTED;

   int res;
    if( AES_KEY_128 == keySizeBytes  * 8)
        res = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    else if( AES_KEY_192 == keySizeBytes  * 8)
        res = EVP_DecryptInit_ex(ctx, EVP_aes_192_gcm(), NULL, NULL, NULL);
    else if( AES_KEY_256 == keySizeBytes  * 8) 
        res = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    else
        return OPENSSM_UNEXPECTED;

    if(1 != res )
        return OPENSSM_UNEXPECTED;
    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        return OPENSSM_UNEXPECTED;

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))return OPENSSM_UNEXPECTED;

    /* Provide any AAD data. This can be called zero or more times as
     * required
    //  */
    // if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
    //     return OPENSSM_UNEXPECTED;

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        return OPENSSM_UNEXPECTED;
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        return OPENSSM_UNEXPECTED;

    /* Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0)
    {
        /* Success */
        plaintext_len += len;
        return OPENSSM_SUCCESS;
    }
    else
    {
        /* Verify failed */
        return OPENSSM_SECURE_MSG_MAC_MISMATCH;
    }
}


OpenSSMStatus HandleAES_GCM_Encrypt_doEncrypt(  SecureMsg*              secureMsg, 
                                                AES_GCM_128_Context*    aesGCMContext,
                                                uint16_t                keySizeBytes,
                                                EncryptedMsg*           encryptedMsg, 
                                                size_t                  maxResponseSize )
{
    const  uint32_t MAX_CIPHER_SIZE                   = 4096;
    static uint8_t  ciphertext[ MAX_CIPHER_SIZE ]     = {0};
    // const  uint8_t* NO_ADD_POINTER                    = NULL;
    // const  uint32_t NO_ADD_SIZE                       = 0;

    sgx_aes_gcm_128bit_tag_t mac;
    AES_GCM_EncryptMsg*      encryptRequest = ( AES_GCM_EncryptMsg* )secureMsg->body;
    uint16_t                 plaintextSize  = encryptRequest->dataSize;

    uint32_t                 encryptResponseSize =  sizeof( SecureMsgType )              + 
                                                    sizeof( AES_GCM_EncryptResponseMsg ) + 
                                                    plaintextSize;

    if( maxResponseSize < encryptResponseSize )
        return OPENSSM_ENCRYPTED_MSG_FAILED_RESPONSE_BUFFER_TOO_SMALL;

    // if( SGX_SUCCESS != sgx_rijndael128GCM_encrypt(   (sgx_aes_gcm_128bit_key_t*)&aesGCMContext->key,
    //                                                  encryptRequest->data,
    //                                                  encryptRequest->dataSize,
    //                                                  ciphertext,
    //                                                  aesGCMContext->iv.asBytes,
    //                                                  sizeof( aesGCMContext->iv ),
    //                                                  NO_ADD_POINTER,
    //                                                  NO_ADD_SIZE,
    //                                                  &mac ) )
    
    if( OPENSSM_SUCCESS != LibreSSL_AESGCM_Encrypt(  (uint8_t*) &aesGCMContext->key,
                                                     keySizeBytes, 
                                                     encryptRequest->data,
                                                     encryptRequest->dataSize,
                                                     ciphertext,
                                                     aesGCMContext->iv.asBytes,
                                                     sizeof( aesGCMContext->iv ),
                                                     (uint8_t*)&mac ) 

        )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_UNEXPECTED_ERROR );
    
    secureMsg->type                             = MK_RESPONSE(AES_GCM_ENCRYPT);
    AES_GCM_EncryptResponseMsg* encryptResponse = ( AES_GCM_EncryptResponseMsg* )secureMsg->body;
    memcpy( encryptResponse->iv.asBytes, &aesGCMContext->iv, sizeof( aesGCMContext->iv ) );
    memcpy( &encryptResponse->tag, &mac,              sizeof( sgx_aes_gcm_128bit_tag_t ) );
    memcpy( encryptResponse->cipherText, ciphertext, plaintextSize );
    encryptResponse->cipherSize = plaintextSize;

    aesGCMContext->iv.counter++;
    return EncryptSecureMsg( secureMsg, encryptResponseSize, encryptedMsg );
}

OpenSSMStatus HandleAES_GCM_Decrypt_doDecrypt(  SecureMsg*              secureMsg, 
                                                AES_GCM_128_Context*    aesGCMContext,
                                                uint16_t                keySizeBytes,
                                                EncryptedMsg*           encryptedMsg, 
                                                size_t                  maxResponseSize )
{
    const  uint32_t MAX_PLAIN_SIZE                    = 4096;
    static uint8_t  plaintext[ MAX_PLAIN_SIZE ]       = {0};
    // const  uint8_t* NO_ADD_POINTER                    = NULL;
    // const  uint32_t NO_ADD_SIZE                       = 0;

    AES_GCM_DecryptMsg*      decryptRequest = ( AES_GCM_DecryptMsg* )secureMsg->body;
    uint16_t                 cipherSize     = decryptRequest->cipherSize;

    uint32_t                 encryptResponseSize =  sizeof( SecureMsgType )              + 
                                                    sizeof( AES_GCM_DecryptResponseMsg ) + 
                                                    cipherSize;

    if( maxResponseSize < encryptResponseSize )
        return OPENSSM_ENCRYPTED_MSG_FAILED_RESPONSE_BUFFER_TOO_SMALL;

    // sgx_status_t ret = sgx_rijndael128GCM_decrypt(   (sgx_aes_gcm_128bit_key_t*)&aesGCMContext->key,
    //                                                  decryptRequest->cipherText,
    //                                                  decryptRequest->cipherSize,
    //                                                  plaintext,
    //                                                  decryptRequest->iv.asBytes,
    //                                                  sizeof( decryptRequest->iv ),
    //                                                  NO_ADD_POINTER,
    //                                                  NO_ADD_SIZE,
    //                                                  &decryptRequest->tag );

    OpenSSMStatus ret = LibreSSL_AESGCM_Decrypt( (uint8_t*)&aesGCMContext->key,
                                                 keySizeBytes,
                                                 decryptRequest->cipherText,
                                                 decryptRequest->cipherSize,
                                                 plaintext,
                                                 decryptRequest->iv.asBytes,
                                                 sizeof( decryptRequest->iv ),
                                                 (uint8_t*)&decryptRequest->tag );

    if( OPENSSM_SECURE_MSG_MAC_MISMATCH == ret ) 
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_MAC_MISMATCH );
    if( OPENSSM_SUCCESS != ret )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_UNEXPECTED_ERROR );
    
    secureMsg->type                             = MK_RESPONSE(AES_GCM_DECRYPT);
    AES_GCM_DecryptResponseMsg* decryptResponse = ( AES_GCM_DecryptResponseMsg* )secureMsg->body;
    decryptResponse->plainSize                  = cipherSize;
    memcpy( decryptResponse->plainText, plaintext, cipherSize );
   
    return EncryptSecureMsg( secureMsg, encryptResponseSize, encryptedMsg );
}

OpenSSMStatus HandleSignECDSA_OpenSSL(  SecureMsg*      secureMsg, 
                                        uint32_t        secureMsgSize,
                                        EncryptedMsg*   encryptedMsg, 
                                        size_t          maxResponseSize )
{
    //HandleSignRSA_verifySize is also suitable for ECDSA
    OpenSSMStatus ret = HandleSignRSA_verifySize( secureMsg, secureMsgSize );
    if( OPENSSM_SUCCESS != ret )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, ret );

    ECDSASignOpenSSLMsg* signECDSAMsg      = ( ECDSASignOpenSSLMsg* )secureMsg->body;

    if( ssmContext.keyStore.find( signECDSAMsg->keyHandle ) == ssmContext.keyStore.end() )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_BAD_HANDLE );

    KeyObject *keyObject = ( KeyObject* )ssmContext.keyStore[ signECDSAMsg->keyHandle ];
    if( keyObject->type != ECDSA_OPENSSL_KEY )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_BAD_HANDLE );

    if( false == keyObject->attributes.canBeUsedForSigning )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_SIGNING_NOT_ALLOWED_IN_ATTRIBUTES );

    return HandleSignECDSAOpenSSL_sign(  secureMsg, 
                                        // ( EVP_PKEY* )keyObject->object, 
                                        ( DrawerManager* )keyObject->object,
                                        encryptedMsg, 
                                        maxResponseSize );

    // return HandleSignRSA_sign(  secureMsg, 
    //                             // ( EVP_PKEY* )keyObject->object, 
    //                             ( DrawerManager* )keyObject->object,
    //                             encryptedMsg, 
    //                             maxResponseSize );
    return OPENSSM_SUCCESS;
}

OpenSSMStatus HandleSignRSA(    SecureMsg*      secureMsg, 
                                uint32_t        secureMsgSize,
                                EncryptedMsg*   encryptedMsg, 
                                size_t          maxResponseSize )
{
    OpenSSMStatus ret = HandleSignRSA_verifySize( secureMsg, secureMsgSize );
    if( OPENSSM_SUCCESS != ret )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, ret );

    RSASignMsg* signRSAMsg      = ( RSASignMsg* )secureMsg->body;

    if( ssmContext.keyStore.find( signRSAMsg->keyHandle ) == ssmContext.keyStore.end() )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_BAD_HANDLE );

    KeyObject *keyObject = ( KeyObject* )ssmContext.keyStore[ signRSAMsg->keyHandle ];
    if( keyObject->type != RSA_KEY )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_BAD_HANDLE );

    if( false == keyObject->attributes.canBeUsedForSigning )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_SIGNING_NOT_ALLOWED_IN_ATTRIBUTES );


    return HandleSignRSA_sign(  secureMsg, 
                                // ( EVP_PKEY* )keyObject->object, 
                                ( DrawerManager* )keyObject->object,
                                encryptedMsg, 
                                maxResponseSize );
}            

inline KeyObject* GetKeyObject( uint64_t keyHandle )
{
    if( ssmContext.keyStore.find( keyHandle ) == ssmContext.keyStore.end() )
        return NULL;

    return ( KeyObject* )ssmContext.keyStore[ keyHandle ];
}

OpenSSMStatus HandleAES_CMAC(   SecureMsg*      secureMsg, 
                                uint32_t        secureMsgSize,
                                EncryptedMsg*   encryptedMsg, 
                                size_t          maxResponseSize )
{
    OpenSSMStatus ret = HandleAES_GCM_Encrypt_verifySize( secureMsg, secureMsgSize );
    if( OPENSSM_SUCCESS != ret )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, ret );
 
    AES_CMAC_Msg* aesEncryptMsg      = ( AES_CMAC_Msg* )secureMsg->body;

    KeyObject *keyObject = GetKeyObject( aesEncryptMsg->keyHandle  );
    if( NULL == keyObject || keyObject->type != AES_GCM_128_KEY  )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_BAD_HANDLE );
    if( false == keyObject->attributes.canBeUSedForMAC)
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_OPERATION_NOT_ALLOWED_IN_ATTRIBUTES );
 
    return HandleAES_CMAC_doCMAC(   secureMsg, 
                                    ( AES_GCM_128_Context* )keyObject->object, 
                                    encryptedMsg, 
                                    maxResponseSize );
}

OpenSSMStatus HandleAES_GCM_Encrypt(    SecureMsg*      secureMsg, 
                                        uint32_t        secureMsgSize,
                                        EncryptedMsg*   encryptedMsg, 
                                        size_t          maxResponseSize )
{
    OpenSSMStatus ret = HandleAES_GCM_Encrypt_verifySize( secureMsg, secureMsgSize );
    if( OPENSSM_SUCCESS != ret )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, ret );
 
    AES_GCM_EncryptMsg* aesEncryptMsg      = ( AES_GCM_EncryptMsg* )secureMsg->body;

    KeyObject *keyObject = GetKeyObject( aesEncryptMsg->keyHandle  );
    if( NULL == keyObject  )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_BAD_HANDLE );
    if( keyObject->type != AES_KEY_128 && keyObject->type != AES_KEY_192 && keyObject->type != AES_KEY_256 )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_BAD_HANDLE );
    if( false == keyObject->attributes.canBeUSedForEncrypting )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_OPERATION_NOT_ALLOWED_IN_ATTRIBUTES );
 
    uint16_t keySizeBytes = keyObject->type / 8;
    return HandleAES_GCM_Encrypt_doEncrypt(  secureMsg, 
                                            ( AES_GCM_128_Context* )keyObject->object, 
                                            keySizeBytes,
                                            encryptedMsg, 
                                            maxResponseSize );
}

OpenSSMStatus HandleAES_GCM_Decrypt(    SecureMsg*      secureMsg, 
                                        uint32_t        secureMsgSize,
                                        EncryptedMsg*   encryptedMsg, 
                                        size_t          maxResponseSize )
{
    OpenSSMStatus ret = HandleAES_GCM_Decrypt_verifySize( secureMsg, secureMsgSize );
    if( OPENSSM_SUCCESS != ret )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, ret );
 
    AES_GCM_DecryptMsg* aesDecryptMsg   = ( AES_GCM_DecryptMsg* )secureMsg->body;
    KeyObject*          keyObject       = GetKeyObject( aesDecryptMsg->keyHandle );

    if( NULL == keyObject )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_BAD_HANDLE );
    if( keyObject->type != AES_KEY_128 && keyObject->type != AES_KEY_192 && keyObject->type != AES_KEY_256 )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_BAD_HANDLE );
    if( false == keyObject->attributes.canBeUSedForEncrypting )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_OPERATION_NOT_ALLOWED_IN_ATTRIBUTES );

    uint16_t keySizeBytes = keyObject->type / 8;
    return HandleAES_GCM_Decrypt_doDecrypt(  secureMsg, 
                                            ( AES_GCM_128_Context* )keyObject->object, 
                                            keySizeBytes,
                                            encryptedMsg, 
                                            maxResponseSize );
}      

void SealAllowedUsers()
{
    const uint32_t NO_AAD           = 0;
    const uint8_t* NO_ADD_POINTER   = NULL;
    const uint32_t sizeOfAllowedUsers = ssmContext.allowedUsers.size() * sizeof( UserPermissions );

    uint32_t sealedDataSize = sgx_calc_sealed_data_size( NO_AAD, sizeOfAllowedUsers );
        
    uint8_t sealedAllowedUsers[ sealedDataSize ]; 

    sgx_attributes_t attribute_mask;
    attribute_mask.flags = SGX_FLAGS_RESERVED | SGX_FLAGS_INITTED | SGX_FLAGS_DEBUG;
    attribute_mask.xfrm = 0x0;

    sgx_status_t err = sgx_seal_data_ex(    SGX_KEYPOLICY_MRENCLAVE, 
                                            attribute_mask, 
                                            TSEAL_DEFAULT_MISCMASK, 
                                            NO_AAD,
                                            NO_ADD_POINTER, 
                                            sizeOfAllowedUsers, 
                                            ( uint8_t* )&ssmContext.allowedUsers[0],  //c++ standard guarantees vectors are contingous in memory 
                                            sealedDataSize, 
                                            ( sgx_sealed_data_t* )sealedAllowedUsers );

    if( SGX_SUCCESS != err )
        printf("############ %s: %d: Error sealing allowed users\n", __FUNCTION__, __LINE__ );

    sgx_sealed_data_t *sealingMetaData = ( sgx_sealed_data_t* )sealedAllowedUsers; 
    memcpy( ssmContext.allowedUsersTag, &sealingMetaData->aes_data.payload_tag, sizeof( sgx_aes_gcm_128bit_tag_t ) );
    
    
    OpenSSMStatus status;
    err = OcallSaveAllowedUsers( (uint32_t*)&status, sealedAllowedUsers, sealedDataSize ); 

    if( err != SGX_SUCCESS || status != OPENSSM_SUCCESS )
        printf("############ %s: %d: Error sealing allowed users\n", __FUNCTION__, __LINE__ );
}



void AddUserToAllowedUsers( UserID                      userID, 
                            const AllowedServicesMap    *allowedServicesMap )
{
    UserPermissions newUser;
    memcpy( &newUser.userID, &userID, sizeof( UserID ) );
    memcpy( &newUser.allowedServicesMap, allowedServicesMap, sizeof( AllowedServicesMap ) );
    
    ssmContext.allowedUsers.push_back( newUser ); //will copy newUser to vector. Local newUser will be automatically destroyed

    SealAllowedUsers();
}

OpenSSMStatus HandleAllowUserRegistration(  SecureMsg*      secureMsg, 
                                            uint32_t        secureMsgSize,
                                            EncryptedMsg*   encryptedMsg, 
                                            size_t          maxResponseSize )
{
    if( secureMsgSize != sizeof( SecureMsgType ) + sizeof( AllowUserRegistrationMsg ) )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_BAD_SIZE );
 
    AllowUserRegistrationMsg* allowUserMsg   = ( AllowUserRegistrationMsg* )secureMsg->body;
    
    AddUserToAllowedUsers( allowUserMsg->userID, &allowUserMsg->allowedServicesMap );

    uint32_t             encryptResponseSize = sizeof( SecureMsgType );
    secureMsg->type                          = MK_RESPONSE( ALLOW_USER_REGISTRATION );

    return EncryptSecureMsg( secureMsg, encryptResponseSize, encryptedMsg ); 
}      

UserID* GetCurrentUserID()
{
    if( ssmContext.currentUserIdx < 0 || 
        ( uint32_t )ssmContext.currentUserIdx > ssmContext.usersSharedKeys.size() )
        return NULL;

    return &ssmContext.usersSharedKeys[ ssmContext.currentUserIdx ].userID;
}

OpenSSMStatus HandleProveSSMIDentity(   SecureMsg*      secureMsg, 
                                        uint32_t        secureMsgSize,
                                        EncryptedMsg*   encryptedMsg, 
                                        size_t          maxResponseSize )
{
    if( secureMsgSize != sizeof( SecureMsgType ) )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_BAD_SIZE );
 
    uint32_t encryptResponseSize = sizeof( SecureMsgType ) + sizeof( ProveSSMIdentityResponse );
    if( maxResponseSize < encryptResponseSize )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_BUFFER_TOO_SMALL );       

    ProveSSMIdentityResponse* proofResponse   = ( ProveSSMIdentityResponse* )secureMsg->body;

    if( OPENSSM_SUCCESS != GenerateSSMProofOfIdentity( ( sgx_sha256_hash_t* )GetCurrentUserID(), 
                                                        &proofResponse->ssmProofOfIdentity ) )
        return OPENSSM_ESTABLISH_SESSION_FAILED_UNEXPECTED;

    secureMsg->type = MK_RESPONSE( PROVE_SSM_IDENTITY );

    return EncryptSecureMsg( secureMsg, encryptResponseSize, encryptedMsg ); 
}  

OpenSSMStatus ExpungeKeyIfExpired( KeyObject *keyObject )
{
    if( keyObject->attributes.storeOnDisk == false )
        return OPENSSM_SUCCESS;

    switch( keyObject->type )
    {
        case ECDSA_KEY:
            free( keyObject->object );
        break;
        default:
            return OPENSSM_UNEXPECTED;
    }

    ssmContext.keyStore.erase( keyObject->handle );

    return OPENSSM_SUCCESS;
}

OpenSSMStatus HandleSignECDSA(    SecureMsg*      secureMsg, 
                                uint32_t        secureMsgSize,
                                EncryptedMsg*   encryptedMsg, 
                                size_t          maxResponseSize )
{
    OpenSSMStatus ret = HandleSignECDSA_verifySize( secureMsg, secureMsgSize );
    if( OPENSSM_SUCCESS != ret )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, ret );

    ECDSASignMsg* signMsg      = ( ECDSASignMsg* )secureMsg->body;

    KeyObject *keyObject = GetKeyObject( signMsg->keyHandle  );

    if( NULL == keyObject || keyObject->type != ECDSA_KEY )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_BAD_HANDLE );

    if( false == keyObject->attributes.canBeUsedForSigning )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_SIGNING_NOT_ALLOWED_IN_ATTRIBUTES );

    sgx_ec256_signature_t signature = {0};
    if( OPENSSM_SUCCESS !=  HandleSignECDSA_sign(   signMsg->data,
                                                    signMsg->dataSize,
                                                    ( sgx_ec256_private_t* )keyObject->object,                                                     
                                                    &signature ) )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_UNEXPECTED_ERROR );

    if( OPENSSM_SUCCESS != ExpungeKeyIfExpired( keyObject ) )
        return ReportErrorInSecureMsg( secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_UNEXPECTED_ERROR );

    return HandleSignECDSA_reply(   secureMsg, 
                                    &signature, 
                                    encryptedMsg, 
                                    maxResponseSize );
}                                      


bool IsServiceAllowed( uint16_t serviceID ){
    if( serviceID >= ssmContext.servicesTable.numEntries )
        return false;
    if( ssmContext.servicesTable.handlers[ serviceID ] == NULL )    
        return false;
    if( NULL == ssmContext.lastApprovedUser )
        return true; //We have an insecure session. This is NOT SECURE


    // printf( "############# ssmContext.lastApprovedUser = %p\n", ssmContext.lastApprovedUser );
    // bool serviceAllowed = ssmContext.lastApprovedUser->allowedServicesMap[ serviceID ];
    // if( serviceAllowed )
    //     printf( "############# Service %d is ALLOWED\n", serviceID );
    // else
    //     printf( "############# Service %d is NOT ALLOWED\n", serviceID );

    return ssmContext.lastApprovedUser->allowedServicesMap[ serviceID ];
}

OpenSSMStatus EcallUnsealAllowedUsers( uint8_t* sealedAllowedUsers,  uint32_t sealedDataSize   )
{
    uint32_t aadSize = 0;
    uint8_t* aad     = NULL;
    
    if( sealedDataSize < sizeof(sgx_sealed_data_t) )
        return OPENSSM_BUFFER_TOO_SMALL;
    
    uint32_t unsealedDataSize = sealedDataSize - sizeof(sgx_sealed_data_t);
    
    if( unsealedDataSize % sizeof( UserPermissions ) != 0 ) 
        return OPENSSM_CANT_UNSEAL_MASTER_SECRETS;
    
    uint16_t numAllowedUsers = unsealedDataSize / sizeof( UserPermissions );
    if( numAllowedUsers > MAX_SSM_USERS || numAllowedUsers == 0)
        return OPENSSM_CANT_UNSEAL_MASTER_SECRETS;
    
    UserPermissions tempAllowedUsers[ numAllowedUsers ];
    sgx_status_t    err                     = SGX_ERROR_UNEXPECTED;
    uint32_t        actualUnsealedDataSize  = unsealedDataSize;
    err = sgx_unseal_data( ( sgx_sealed_data_t* )sealedAllowedUsers,
                            aad,
                            &aadSize,
                            (uint8_t*)tempAllowedUsers,
                            &actualUnsealedDataSize );
    
    if( SGX_SUCCESS != err )
        return OPENSSM_CANT_UNSEAL_MASTER_SECRETS;
    if( unsealedDataSize != actualUnsealedDataSize || aadSize != 0 )
        return OPENSSM_CANT_UNSEAL_MASTER_SECRETS;
    
    //The off-by-one is intentional, according to "vector:assign" documentation
    ssmContext.allowedUsers.assign( &tempAllowedUsers[ 0 ], &tempAllowedUsers[ numAllowedUsers ] ); 

    sgx_sealed_data_t *sealingMetaData = ( sgx_sealed_data_t* )sealedAllowedUsers; 
    memcpy( ssmContext.allowedUsersTag, &sealingMetaData->aes_data.payload_tag, sizeof( sgx_aes_gcm_128bit_tag_t ) );
    
    return OPENSSM_SUCCESS;
}


OpenSSMStatus EcallHandleEncryptedMsg(  EncryptedMsg*   encryptedMsg, 
                                        size_t          maxResponseSize )
{
    // static SecureMsg secureMsg;
    SecureMsg secureMsg;

    if( encryptedMsg->cipherSize + sizeof( EncryptedMsg ) > maxResponseSize )
        // cipherSize is actually bigger than buffer copied inside the enclave
        return OPENSSM_ENCRYPTED_MSG_FAILED_BAD_MSG;
    
    if( encryptedMsg->cipherSize >= SECURE_MSG_BUFFER_SIZE )
        return OPENSSM_ENCRYPTED_MSG_FAILED_BAD_MSG;
    
    OpenSSMStatus ret = DecryptSecureMsg( encryptedMsg, &secureMsg );    
    if( ret != OPENSSM_SUCCESS )
    {   
        return ret;
    }
    
    // uint32_t responseSize  = 0;
    uint32_t secureMsgSize = encryptedMsg->cipherSize;
        
    if( ! IsServiceAllowed( secureMsg.type ) ){
        printf("#############3 unknown secureMsg.Type: %d\n", secureMsg.type );
        return ReportErrorInSecureMsg( &secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_UNKNOWN_MSG );        
    }
    
    return ssmContext.servicesTable.handlers[ secureMsg.type ]( &secureMsg, 
                                                                secureMsgSize, 
                                                                encryptedMsg, 
                                                                maxResponseSize );
    
    // switch( secureMsg.type )
    // {
    //     case PING:
    //         //Echo ping back
    //         responseSize = encryptedMsg->cipherSize + sizeof( EncryptedMsg );
    //         if( responseSize > maxResponseSize )
    //             return OPENSSM_ENCRYPTED_MSG_FAILED_RESPONSE_BUFFER_TOO_SMALL;
            
    //         return EncryptSecureMsg( &secureMsg, encryptedMsg->cipherSize ,encryptedMsg );

    //     case RSA_GENERATE_KEY_PAIR_REQUEST:
    //         return HandleGenerateKeyPairRSA(    &secureMsg, 
    //                                             secureMsgSize, 
    //                                             encryptedMsg, 
    //                                             maxResponseSize );

    //     case RSA_SIGN_REQUEST:
    //         return HandleSignRSA(   &secureMsg, 
    //                                 secureMsgSize, 
    //                                 encryptedMsg, 
    //                                 maxResponseSize );

    //     case ECDSA_GENERATE_KEY_PAIR_REQUEST:
    //         return HandleGenerateKeyPairECDSA(  &secureMsg, 
    //                                             secureMsgSize, 
    //                                             encryptedMsg, 
    //                                             maxResponseSize );

    //     case ECDSA_SIGN_REQUEST:
    //         return HandleSignECDSA( &secureMsg, 
    //                                 secureMsgSize, 
    //                                 encryptedMsg, 
    //                                 maxResponseSize );

    //     case AES_GCM_GENERATE_KEY_REQUEST:
    //         return HandleGenerateKeyAES_GCM(    &secureMsg, 
    //                                             secureMsgSize, 
    //                                             encryptedMsg, 
    //                                             maxResponseSize );

    //     case AES_GCM_ENCRYPT_REQUEST:        
    //         return HandleAES_GCM_Encrypt(   &secureMsg, 
    //                                         secureMsgSize, 
    //                                         encryptedMsg, 
    //                                         maxResponseSize );

    //     case AES_CMAC_REQUEST:
    //         return HandleAES_CMAC(  &secureMsg, 
    //                                 secureMsgSize, 
    //                                 encryptedMsg, 
    //                                 maxResponseSize );

    //     case AES_GCM_DECRYPT_REQUEST:
    //         return HandleAES_GCM_Decrypt(   &secureMsg, 
    //                                         secureMsgSize, 
    //                                         encryptedMsg, 
    //                                         maxResponseSize );

    //     case ALLOW_USER_REGISTRATION_REQUEST:
    //         return HandleAllowUserRegistration( &secureMsg, 
    //                                             secureMsgSize, 
    //                                             encryptedMsg, 
    //                                             maxResponseSize );
    //     case PROVE_SSM_IDENTITY_REQUEST:
    //         return HandleProveSSMIDentity     ( &secureMsg, 
    //                                             secureMsgSize, 
    //                                             encryptedMsg, 
    //                                             maxResponseSize );

    //     case ARM_KEY_REQUEST:
    //         return HandleArmKey               ( &secureMsg, 
    //                                             secureMsgSize, 
    //                                             encryptedMsg, 
    //                                             maxResponseSize );

    //     case GET_CHALLENGE_REQUEST:
    //         return HandleGetChallenge         ( &secureMsg, 
    //                                             secureMsgSize, 
    //                                             encryptedMsg, 
    //                                             maxResponseSize );

    //     case IMPORT_RSA_KEY_REQUEST:
    //         return HandleImportRSAKey         ( &secureMsg, 
    //                                             secureMsgSize, 
    //                                             encryptedMsg, 
    //                                             maxResponseSize );

    //     case CREATE_ACCOUNT_REQUEST:
    //         return HandleCreateAccount         ( &secureMsg, 
    //                                             secureMsgSize, 
    //                                             encryptedMsg, 
    //                                             maxResponseSize );

    //     case TRANSACTION_REQUEST:
    //         return HandleTransaction          ( &secureMsg, 
    //                                             secureMsgSize, 
    //                                             encryptedMsg, 
    //                                             maxResponseSize );

    //     default:
    //         printf("############ unknown secure msg type: 0x%x\n", secureMsg.type  );
    //         return ReportErrorInSecureMsg( &secureMsg, encryptedMsg, maxResponseSize, OPENSSM_SECURE_MSG_UNKNOWN_MSG );
    // }
 
    // return OPENSSM_SUCCESS;
}

uint64_t EcallGetSync()
{
    return ssmContext.sessionContext.decryptionIV.msgCounter;

}
uint32_t CalcSharedKeysSize()
{
    uint16_t numSharedKeys = ssmContext.usersSharedKeys.size();
    return sizeof( SharedKeys ) * numSharedKeys;
}

uint32_t EcallSealMasterSecrets_getSealedDataSize()
{
    const uint32_t NO_AAD = 0;
    return sgx_calc_sealed_data_size( NO_AAD, CalcSharedKeysSize() );
}

OpenSSMStatus EcallSealMasterSecrets( uint8_t* sealedMasterKeys, uint32_t sealedDataSize )
{
    const uint32_t NO_AAD           = 0;
    const uint8_t* NO_ADD_POINTER   = NULL;
    const uint32_t sizeOfSharedKeys = CalcSharedKeysSize();

    if( sealedDataSize != sgx_calc_sealed_data_size( NO_AAD, sizeOfSharedKeys ) )
        return OPENSSM_BUFFER_TOO_SMALL;

    sgx_status_t err = SGX_ERROR_UNEXPECTED;
    sgx_attributes_t attribute_mask;
    attribute_mask.flags = SGX_FLAGS_RESERVED | SGX_FLAGS_INITTED | SGX_FLAGS_DEBUG;
    attribute_mask.xfrm = 0x0;

    err = sgx_seal_data_ex( SGX_KEYPOLICY_MRENCLAVE, 
                            attribute_mask, 
                            TSEAL_DEFAULT_MISCMASK, 
                            NO_AAD,
                            NO_ADD_POINTER, 
                            sizeOfSharedKeys, 
                            ( uint8_t* )&ssmContext.usersSharedKeys[0],  //c++ standard guarantees vectors are contingous in memory 
                            sealedDataSize, 
                            ( sgx_sealed_data_t* )sealedMasterKeys );

    if( SGX_SUCCESS != err )
        return OPENSSM_CANT_SEAL_MASTER_SECRETS;

    return OPENSSM_SUCCESS;
}

OpenSSMStatus EcallUnsealMasterSecrets( uint8_t* sealedMasterKeys, uint32_t sealedDataSize )
{
    uint32_t aadSize = 0;
    uint8_t* aad     = NULL;
    
    if( sealedDataSize < sizeof(sgx_sealed_data_t) )
        return OPENSSM_BUFFER_TOO_SMALL;
    
    uint32_t unsealedDataSize = sealedDataSize - sizeof(sgx_sealed_data_t);
    
    if( unsealedDataSize % sizeof( SharedKeys ) != 0 ) 
        return OPENSSM_CANT_UNSEAL_MASTER_SECRETS;
    
    uint16_t numSharedKeys = unsealedDataSize / sizeof( SharedKeys );
    if( numSharedKeys > MAX_SSM_USERS || numSharedKeys == 0)
        return OPENSSM_CANT_UNSEAL_MASTER_SECRETS;
    
    SharedKeys tempSharedKeys[ numSharedKeys ];
    sgx_status_t    err                     = SGX_ERROR_UNEXPECTED;
    uint32_t        actualUnsealedDataSize  = unsealedDataSize;
    err = sgx_unseal_data( ( sgx_sealed_data_t* )sealedMasterKeys,
                            aad,
                            &aadSize,
                            (uint8_t*)tempSharedKeys,
                            &actualUnsealedDataSize );
    
    if( SGX_SUCCESS != err )
        return OPENSSM_CANT_UNSEAL_MASTER_SECRETS;
    if( unsealedDataSize != actualUnsealedDataSize || aadSize != 0 )
        return OPENSSM_CANT_UNSEAL_MASTER_SECRETS;
    
    //The off-by-one is intentional, according to "vector:assign" documentation
    ssmContext.usersSharedKeys.assign( &tempSharedKeys[ 0 ], &tempSharedKeys[ numSharedKeys ] ); 

    return OPENSSM_SUCCESS;
}


void SetupServicesTable( ServicesTable& servicesTable ) {
    servicesTable.numEntries = NUM_SERVICES;
    servicesTable.handlers   = ( ServiceCallback* )malloc( sizeof( ServiceCallback ) * NUM_SERVICES );
    memset( servicesTable.handlers, 0, sizeof( ServiceCallback ) * NUM_SERVICES );
    
    servicesTable.handlers[ PING                            ] = ( ServiceCallback ) HandlePing;
    servicesTable.handlers[ RSA_GENERATE_KEY_PAIR           ] = ( ServiceCallback ) HandleGenerateKeyPairRSA;
    servicesTable.handlers[ RSA_SIGN                        ] = ( ServiceCallback ) HandleSignRSA;
    servicesTable.handlers[ ECDSA_GENERATE_KEY_PAIR         ] = ( ServiceCallback ) HandleGenerateKeyPairECDSA;
    servicesTable.handlers[ ECDSA_SIGN                      ] = ( ServiceCallback ) HandleSignECDSA;
    servicesTable.handlers[ AES_GCM_GENERATE_KEY            ] = ( ServiceCallback ) HandleGenerateKeyAES_GCM;
    servicesTable.handlers[ AES_GCM_ENCRYPT                 ] = ( ServiceCallback ) HandleAES_GCM_Encrypt;
    servicesTable.handlers[ AES_GCM_DECRYPT                 ] = ( ServiceCallback ) HandleAES_GCM_Decrypt;
    servicesTable.handlers[ ALLOW_USER_REGISTRATION         ] = ( ServiceCallback ) HandleAllowUserRegistration;
    servicesTable.handlers[ PROVE_SSM_IDENTITY              ] = ( ServiceCallback ) HandleProveSSMIDentity;
    servicesTable.handlers[ ARM_KEY                         ] = ( ServiceCallback ) HandleArmKey;
    servicesTable.handlers[ GET_CHALLENGE                   ] = ( ServiceCallback ) HandleGetChallenge;
    servicesTable.handlers[ IMPORT_RSA_KEY                  ] = ( ServiceCallback ) HandleImportRSAKey;
    servicesTable.handlers[ AES_CMAC                        ] = ( ServiceCallback ) HandleAES_CMAC;
    servicesTable.handlers[ CREATE_ACCOUNT                  ] = ( ServiceCallback ) HandleCreateAccount;
    servicesTable.handlers[ TRANSACTION                     ] = ( ServiceCallback ) HandleTransaction;
    servicesTable.handlers[ GET_CONFIG_ID                   ] = ( ServiceCallback ) HandleGetConfigID;
    servicesTable.handlers[ ECDSA_GENERATE_KEY_PAIR_OPENSSL ] = ( ServiceCallback ) HandleGenerateKeyPairECDSA_OpenSSL;
    servicesTable.handlers[ ECDSA_SIGN_OPENSSL              ] = ( ServiceCallback ) HandleSignECDSA_OpenSSL;
}

#ifdef __cplusplus
extern "C" {
#endif

void get_custom_entropy( void *buf, size_t n )
{
    // printf("######################## get_custom_entropy called\n" );
    sgx_status_t ret = sgx_read_rand( ( unsigned char* )buf, n );
    if( ret != SGX_SUCCESS )
    {
        printf("\nsgx_read_rand failed with error 0x%0x. Aborting\n", ret );
        abort();
    }

    // printf(" Got entropy!\n");
}

OpenSSMStatus CalcUserID( const sgx_ra_msg2_t * p_msg2, sgx_sha256_hash_t *userID )
{
    if( SGX_SUCCESS != sgx_sha256_msg(  ( uint8_t* )&p_msg2->g_b, 
                                        sizeof( sgx_ec256_public_t ), 
                                        userID ) )
        return OPENSSM_UNEXPECTED;

    return OPENSSM_SUCCESS;
}

sgx_status_t SSM_ProcessMsg2(
    sgx_ra_context_t context,
    const sgx_ra_msg2_t *p_msg2,            //(g_b||spid||quote_type|| KDF_ID ||sign_gb_ga||cmac||sig_rl_size||sig_rl)
    const sgx_target_info_t *p_qe_target,
    sgx_report_t *p_report,
    sgx_quote_nonce_t* p_nonce)
{
    UserID userID = {0};
    if( OPENSSM_SUCCESS != CalcUserID( p_msg2, (sgx_sha256_hash_t*)&userID ) )
        return SGX_ERROR_UNEXPECTED;

    if( ! IsSSMInitialized() ) //First user is always approved, add it with full permissions
            AddUserToAllowedUsers( userID, ADMINISTRATOR_ALLOWED_SERVICES );
    
    ssmContext.lastApprovedUser = FindUserPermissions( &userID );
    if( NULL == ssmContext.lastApprovedUser )
        return SGX_ERROR_UNEXPECTED; //User was not allowed by administrator, otherwise we would find his permissions

    ssmContext.attestationState = UserIDApproved;

    return sgx_ra_proc_msg2_trusted(  context,
                                      p_msg2,
                                      p_qe_target,
                                      p_report,
                                      p_nonce );
}

#define CHECK_REF_POINTER(ptr, siz) do {    \
    if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))   \
        return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do { \
    if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))    \
        return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

typedef struct ms_EcallHandleEncryptedMsg_t {
    OpenSSMStatus ms_retval;
    EncryptedMsg* ms_encryptedMsg;
    size_t ms_maxResponseSize;
} ms_EcallHandleEncryptedMsg_t;

static sgx_status_t SGX_CDECL sgx_EcallHandleEncryptedMsg(void* pms)
{
    
    ms_EcallHandleEncryptedMsg_t* ms = SGX_CAST(ms_EcallHandleEncryptedMsg_t*, pms);
    sgx_status_t status = SGX_SUCCESS;
    EncryptedMsg* _tmp_encryptedMsg = ms->ms_encryptedMsg;
    size_t _tmp_maxResponseSize = ms->ms_maxResponseSize;
    size_t _len_encryptedMsg = _tmp_maxResponseSize;
    EncryptedMsg* _in_encryptedMsg = NULL;

    CHECK_REF_POINTER(pms, sizeof(ms_EcallHandleEncryptedMsg_t));
    CHECK_UNIQUE_POINTER(_tmp_encryptedMsg, _len_encryptedMsg);

    if (_tmp_encryptedMsg != NULL) {
        _in_encryptedMsg = (EncryptedMsg*)malloc(_len_encryptedMsg);
        if (_in_encryptedMsg == NULL) {
            status = SGX_ERROR_OUT_OF_MEMORY;
            goto err;
        }

        memcpy(_in_encryptedMsg, _tmp_encryptedMsg, _len_encryptedMsg);
    }
    ms->ms_retval = EcallHandleEncryptedMsg(_in_encryptedMsg, _tmp_maxResponseSize);
err:
    if (_in_encryptedMsg) {
        memcpy(_tmp_encryptedMsg, _in_encryptedMsg, _len_encryptedMsg);
        free(_in_encryptedMsg);
    }
    
    return status;
}

void EcallStartResponder( HotCall* hotEcall )
{
    sgx_status_t (*callbacks[1])(void*);
    callbacks[0] = sgx_EcallHandleEncryptedMsg;

    HotCallTable callTable;
    callTable.numEntries = 1;
    callTable.callbacks  = callbacks;

    HotCall_waitForCall( hotEcall, &callTable );
}

#ifdef __cplusplus
};
#endif

// 
// void EcallPrintKeys( sgx_ra_context_t context )
// {
//     sgx_ec_key_128bit_t mk_key;
//     sgx_ec_key_128bit_t sk_key;

//     sgx_status_t ret = sgx_ra_get_keys(context, SGX_RA_KEY_MK, &mk_key);
//     if(SGX_SUCCESS != ret)
//     {
//         printf("sgx_ra_get_keys FAILED! Error = 0x%x\n", ret );
//         return;
//     }

//     printf("---------------------mk_key:\n");
//     uint8_t* key = ( uint8_t* )mk_key;
//     for( uint32_t i = 0; i < sizeof( sgx_ec_key_128bit_t ); ++i )
//     {
//         printf("0x%02x, ", key[ i ] );
//         if( ( i + 1 ) % 8 == 0 )
//             printf("\n");
//     }
//     printf("\n");

//     ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
//     if(SGX_SUCCESS != ret)
//     {
//         printf("sgx_ra_get_keys FAILED! Error = 0x%x\n", ret );
//         return;
//     }

//     printf("---------------------mk_key:\n");
//     key = ( uint8_t* )sk_key;
//     for( uint32_t i = 0; i < sizeof( sgx_ec_key_128bit_t ); ++i )
//     {
//         printf("0x%02x, ", key[ i ] );
//         if( ( i + 1 ) % 8 == 0 )
//             printf("\n");
//     }
//     printf("\n");
// }















