#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <pwd.h>
#include <iostream>  
#include <sstream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <vector>

#include "sgx_error.h" /* sgx_status_t */
#include "sgx_eid.h"   /* sgx_enclave_id_t */
#include "sgx_urts.h"
#include "sgx_tseal.h" //sgx_sealed_data_t

// Needed to call untrusted key exchange library APIs, i.e. sgx_ra_proc_msg2.
#include "sgx_ukey_exchange.h"
#include "sgx_key_exchange.h"

// Needed to query extended epid group id.
#include "sgx_uae_service.h"

#include "App.h"
#include "Enclave_u.h"
#include "openssm_server.h"

#include <sys/stat.h>

#define MAX_PATH                     FILENAME_MAX
#define SEALED_MASTER_KEYS_FILE_PATH "sealed_master_keys.bin"
#define SEALED_ALLOWED_USERS_FILE_PATH "sealed_allowed_users.bin"
#define KEYS_DIRECTORY               "keys"

static bool debugTable[ NUM_WORKER_THREADS ] = {0};

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

static Logger  ocallLogger( "OpenSSMServer-ocall");

OpenSSMServer::OpenSSMServer(  NetworkManager &networkManager, bool useHotCalls ): 
                                    mEnclaveID              ( 0 ), 
                                    mEnclaveWasInitialized  ( false ),
                                    mLogger                 ( "OpenSSMServer" ),
                                    mNetworkManager         ( networkManager  ),
                                    mNextAvialableThread    ( 0 ),
                                    mNextThreadToWaitFor    ( -1 )

                                    // mHotCallDispatcher      ( { NULL, 0 } )
                                    
{
    mEnclaveVersion[ 0 ]        = '\0';
    mLogger.mLogLevel           = INFO;
    ocallLogger.mLogLevel       = DEBUG;
    mAttestationState           = WAITING_FOR_SESSION_REQUEST;
    mRemoteAttestationContext   = -1;


    useHotCalls = true;
    // useHotCalls = false;
    if( useHotCalls ) {
        for( uint8_t threadIdx = 0; threadIdx < NUM_WORKER_THREADS; threadIdx++ )
        {
            mHotCallDispatcher[ threadIdx ].hotCall = ( HotCall* ) malloc( sizeof( HotCall ) );
            if( mHotCallDispatcher[ threadIdx ].hotCall != NULL ) { 
                HotCall_init( mHotCallDispatcher[ threadIdx ].hotCall );
                printf("######### %s: %d; allocated HotCall  for thread %d at %p\n", __FUNCTION__, __LINE__, threadIdx, mHotCallDispatcher[ threadIdx ].hotCall );
            }
            else{
                mLogger.Error( "********** Failed allocating HotCalls" );
            }
        }
    }              
}

OpenSSMServer::~OpenSSMServer() {
    if( mEnclaveWasInitialized ) {
        DestroyEnclave();
    }

}

OpenSSMStatus OpenSSMServer::DestroyEnclave()
{
    printf( "Destroying enclave\n" );
    if( SGX_SUCCESS == sgx_destroy_enclave( mEnclaveID ) ) {
        mEnclaveWasInitialized = false;
        return OPENSSM_SUCCESS;
    }
    else {
        return OPENSSM_ENCLAVE_DESTROY_FAILED;
    }
}

const char * OpenSSMServer::Version() const {
    return OPEN_SSM_SERVER_VERSION; 
}

const char * OpenSSMServer::EnclaveVersion() {
    EcallGetVersion( mEnclaveID, mEnclaveVersion, sizeof( mEnclaveVersion ) );
    return mEnclaveVersion;
}

OpenSSMStatus OpenSSMServer::InitEnclave()
{
    printf( "Init enclave\n" );
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &mEnclaveID, NULL);
    if (ret != SGX_SUCCESS) {
        PrintSGXErrorMessage(ret);
        if (fp != NULL) fclose(fp);
        return OPENSSM_ENCLAVE_INIT_FAILED;
    }
    mEnclaveWasInitialized       = true;
    for( uint8_t threadIdx = 0; threadIdx < NUM_WORKER_THREADS; threadIdx++ )
    {
        mHotCallDispatcher[ threadIdx ].enclaveID = mEnclaveID;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return OPENSSM_SUCCESS;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return OPENSSM_SUCCESS;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return OPENSSM_SUCCESS;
}

void OpenSSMServer::SendVersionMsg()
{
    mNetworkMsg[ mNextAvialableThread ].header.totalLength  = (uint16_t)( sizeof( OpenSSMMsgHeader ) + sizeof( VersionMsg ) );
    mNetworkMsg[ mNextAvialableThread ].header.msgType      = RESPONSE_GET_VERSION;
    VersionMsg *versionMsg          = (VersionMsg*)mNetworkMsg[ mNextAvialableThread ].body;

    strncpy( versionMsg->serverVersion, Version(), SERVER_VERSION_LENGTH ); 
    strncpy( versionMsg->enclaveVersion, EnclaveVersion(), ENCLAVE_VERSION_LENGTH );

    versionMsg->serverVersion[ SERVER_VERSION_LENGTH - 1 ]   = '\0';
    versionMsg->enclaveVersion[ ENCLAVE_VERSION_LENGTH - 1 ] = '\0';

    mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
}

void OpenSSMServer::CreateErrorMsg(     OpenSSMStatus   status, 
                                        uint8_t*        extraInfo, 
                                        size_t          extraLength )
{
    mNetworkMsg[ mNextAvialableThread ].header.totalLength  = (uint16_t)( sizeof( OpenSSMMsgHeader ) 
                                                    + sizeof( OpenSSMStatus ) 
                                                    + extraLength );
    mNetworkMsg[ mNextAvialableThread ].header.msgType      = RESPONSE_ERROR;
    ErrorMsg *errorMsg              = (ErrorMsg*)mNetworkMsg[ mNextAvialableThread ].body;
    errorMsg->errorCode             = status;

    size_t availableSapce = MSG_BUFFER_SIZE - offsetof( OpenSSMMsg, body ) - offsetof( ErrorMsg, extraInfo);
    size_t copySize       = extraLength;
    if (copySize > availableSapce )
        copySize = 0;

    memcpy( errorMsg->extraInfo, extraInfo, copySize );
}

OpenSSMStatus OpenSSMServer::RemoteAttestation_getExtendedEPIDGroupID()
{   
    mLogger.Debug( __FUNCTION__ );

    ostringstream   logMsg;
    uint32_t        extended_epid_group_id = 0;
    sgx_status_t    sgxStatus = sgx_get_extended_epid_group_id( &extended_epid_group_id );
    if (SGX_SUCCESS != sgxStatus)
    {
        logMsg << "Call sgx_get_extended_epid_group_id fail. Error = 0x";
        logMsg << std::hex << sgxStatus;
        mLogger.Error( logMsg.str() );

        CreateErrorMsg( OPENSSM_GET_EPID_FAILED, (uint8_t*)&sgxStatus, sizeof( sgxStatus ) );
        mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );   
        return OPENSSM_GET_EPID_FAILED;
    }

    
    if( extended_epid_group_id != 0 )
    {
        logMsg << "Call sgx_get_extended_epid_group_id returned non zero group ID: 0x" << std::hex << extended_epid_group_id;
        mLogger.Error( logMsg.str() );

        CreateErrorMsg( OPENSSM_GET_EPID_RETURNED_NONZERO, (uint8_t*)&extended_epid_group_id, sizeof( extended_epid_group_id ) );
        mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
        return OPENSSM_GET_EPID_RETURNED_NONZERO;
    }

    logMsg << "Call sgx_get_extended_epid_group_id success: 0x" << std::hex << extended_epid_group_id;
    mLogger.Debug( logMsg.str() );
    return OPENSSM_SUCCESS;
}

OpenSSMStatus OpenSSMServer::RemoteAttestation_EcallInitRA()
{   
    mLogger.Debug( __FUNCTION__ );

    ostringstream    logMsg;
    sgx_status_t     ecallStatus                = SGX_SUCCESS;
    sgx_status_t     internalStatus             = SGX_SUCCESS;
    
    mRemoteAttestationContext  = -1;

    ecallStatus = EcallInitRA( mEnclaveID, &internalStatus, &mRemoteAttestationContext );

    if( SGX_SUCCESS != ecallStatus )
    {
        logMsg << "Call EcallInitRA fail. Error = 0x";
        logMsg << std::hex << ecallStatus;
        mLogger.Error( logMsg.str() );

        CreateErrorMsg( OPENSSM_INIT_RA_FAILED, (uint8_t*)&ecallStatus, sizeof( ecallStatus ) );
        mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
        return OPENSSM_INIT_RA_FAILED;
    }

    if( SGX_SUCCESS != internalStatus )
    {
        logMsg << "Call EcallInitRA succeeded, but internal status is bad. Error = 0x";
        logMsg << std::hex << internalStatus;
        mLogger.Error( logMsg.str() );

        sgx_status_t statuses[ 2 ] = { ecallStatus, internalStatus };

        CreateErrorMsg( OPENSSM_INIT_RA_FAILED, (uint8_t*)statuses, sizeof( statuses ) );
        mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
        return OPENSSM_INIT_RA_FAILED;
    }

    logMsg << "Call EcallInitRA succeeded. Context = 0x";
    logMsg << std::hex << mRemoteAttestationContext;
    mLogger.Debug( logMsg.str() );

    return OPENSSM_SUCCESS;
}

OpenSSMStatus OpenSSMServer::RemoteAttestation_GetMessage1( sgx_ra_msg1_t *message1 )
{
    ostringstream logMsg;
    sgx_status_t  status = sgx_ra_get_msg1(  mRemoteAttestationContext, 
                                             mEnclaveID, 
                                             sgx_ra_get_ga, //Using SGX SDK supplied function to generate kry pair
                                             message1 );

    if( SGX_SUCCESS != status )
    {
        logMsg << "Call sgx_ra_get_msg1 fail. Error = 0x";
        logMsg << std::hex << status;
        mLogger.Error( logMsg.str() );

        CreateErrorMsg( OPENSSM_INIT_GET_MSG1_FAILED, (uint8_t*)&status, sizeof( status ) );
        mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
        return OPENSSM_INIT_GET_MSG1_FAILED;
    }

    uint32_t* groupID = (uint32_t*)message1->gid;
    logMsg << "Call sgx_ra_get_msg1 succeeded. GroupID = 0x";
    logMsg << std::hex << *groupID;
    mLogger.Debug( logMsg.str() );

    // uint8_t*      g_a = (uint8_t*)&message1->g_a;
    // ostringstream log_g_a;
    // log_g_a << "Enclave public key (g_a):\n";
    // for( uint32_t i = 0; i < sizeof( sgx_ec256_public_t ); ++i )
    // {
        
    //     log_g_a << "0x" << std::hex << (uint32_t)g_a[ i ] << ", ";
    //     if( ( i + 1 ) % 8 == 0 )
    //         log_g_a << std::endl;
    // }
    // log_g_a << "\n";
    // mLogger.Debug( log_g_a.str() );

    return OPENSSM_SUCCESS;
}



OpenSSMStatus OpenSSMServer::RemoteAttestation_Start_verifyAttestationState()
{
    if( mAttestationState != WAITING_FOR_SESSION_REQUEST )
    {
        ostringstream logMsg;
        logMsg << "Service provider requesting msg1, but corrent attestation state is ";
        logMsg << mAttestationState;
        mLogger.Error( logMsg.str() );

        CreateErrorMsg( OPENSSM_INIT_RA_FAILED_BAD_STATE, NULL, 0 );
        mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
        return OPENSSM_INIT_RA_FAILED_BAD_STATE;
    }

    return OPENSSM_SUCCESS;
}

OpenSSMStatus OpenSSMServer::EstablishSession_verifyAttestationState( SessionKeysScheme scheme )
{
    if( KEY_SCHEME_NULL_ENCRYPTION == scheme )
        return OPENSSM_SUCCESS;

    //We have non trivial keys scheme, we must be after remote attestation process:
    if( mAttestationState != WAITING_FOR_SESSION_REQUEST )
    {
        ostringstream logMsg;
        logMsg << "Service provider requesting to establish session, but corrent attestation state is ";
        logMsg << mAttestationState;
        mLogger.Error( logMsg.str() );

        CreateErrorMsg( OPENSSM_ESTABLISH_SESSION_FAILED_BAD_STATE, NULL, 0 );
        mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
        return OPENSSM_ESTABLISH_SESSION_FAILED_BAD_STATE;
    }

    return OPENSSM_SUCCESS;
}

void OpenSSMServer::RemoteAttestation_Start()
{
    mLogger.Debug( __FUNCTION__ );

    if( OPENSSM_SUCCESS != RemoteAttestation_Start_verifyAttestationState() )
        return;

    if( OPENSSM_SUCCESS != RemoteAttestation_getExtendedEPIDGroupID() )
        return;

    if( OPENSSM_SUCCESS != RemoteAttestation_EcallInitRA() )
        return;

    sgx_ra_msg1_t message1;
    if( OPENSSM_SUCCESS != RemoteAttestation_GetMessage1( &message1 ) )
        return;

    mNetworkMsg[ mNextAvialableThread ].header.totalLength  = (uint16_t)( sizeof( OpenSSMMsgHeader ) 
                                                    + sizeof( message1 ) );
    mNetworkMsg[ mNextAvialableThread ].header.msgType      = RESPONSE_INIT_MSG1;
    memcpy( mNetworkMsg[ mNextAvialableThread ].body, &message1, sizeof( message1 ) );
    mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );

    mAttestationState = WAITING_FOR_MSG2;
}

OpenSSMStatus OpenSSMServer::RemoteAttestation_ProcessMsg2_verifyMsgSize()
{
    uint32_t minimumExpectedSize =  sizeof( OpenSSMMsgHeader ) + 
                                    sizeof( sgx_ra_msg2_t );
    if( mNetworkMsg[ mNextAvialableThread ].header.totalLength < minimumExpectedSize )
    {
        ostringstream logMsg;
        logMsg << "Msg2 is too small. Shold be at least " << minimumExpectedSize ;
        logMsg << " bytes, but got " << mNetworkMsg[ mNextAvialableThread ].header.totalLength << " bytes";
        mLogger.Error( logMsg.str() );

        CreateErrorMsg( OPENSSM_INIT_GET_MSG2_BAD_MSG, NULL, 0 );
        mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
        return OPENSSM_INIT_GET_MSG2_BAD_MSG;
    }

    sgx_ra_msg2_t* msg2 = ( sgx_ra_msg2_t* )mNetworkMsg[ mNextAvialableThread ].body;
    uint32_t expectedSize = sizeof( OpenSSMMsgHeader ) + 
                            sizeof( sgx_ra_msg2_t )    + 
                            msg2->sig_rl_size;

    if( mNetworkMsg[ mNextAvialableThread ].header.totalLength != expectedSize )
    {
        ostringstream logMsg;
        logMsg << "Msg2 is malformed. Expected size = " << expectedSize 
               << " bytes (sizeof( OpenSSMMsgHeader ) + sizeof( sgx_ra_msg2_t ) + msg2->sig_rl_size );"
               << " but got " << mNetworkMsg[ mNextAvialableThread ].header.totalLength << " bytes.";
        mLogger.Error( logMsg.str() );

        CreateErrorMsg( OPENSSM_INIT_GET_MSG2_BAD_MSG, NULL, 0 );
        mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
        return OPENSSM_INIT_GET_MSG2_BAD_MSG;
    }

    return OPENSSM_SUCCESS;
}

OpenSSMStatus OpenSSMServer::EstablishSession_verifyMsgSize()
{
    ostringstream logMsg;
    uint32_t minimumExpectedSize =  sizeof( OpenSSMMsgHeader ) + 
                                    sizeof( EstablishSessionKeysMsg );
    if( mNetworkMsg[ mNextAvialableThread ].header.totalLength < minimumExpectedSize )
    {
        logMsg << "Establish session msg is too small. Shold be at least " << minimumExpectedSize ;
        logMsg << " bytes, but got " << mNetworkMsg[ mNextAvialableThread ].header.totalLength << " bytes";
        mLogger.Error( logMsg.str() );

        CreateErrorMsg( OPENSSM_ESTABLISH_SESSION_FAILED_BAD_MSG, NULL, 0 );
        mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
        return OPENSSM_ESTABLISH_SESSION_FAILED_BAD_MSG;
    }

    EstablishSessionKeysMsg* establishSessionMsg = ( EstablishSessionKeysMsg* )mNetworkMsg[ mNextAvialableThread ].body;
    
    switch( establishSessionMsg->scheme )
    {
        case AES_GCM_128_DOUBLE_NONCE:
        {
            uint32_t expectedSize = sizeof( OpenSSMMsgHeader )          + 
                                    sizeof( EstablishSessionKeysMsg )   +
                                    AES_GCM_128_DOUBLE_NONCE_PAYLOAD_SIZE;
            if( mNetworkMsg[ mNextAvialableThread ].header.totalLength != expectedSize )
            {
                logMsg << "Establish session msg with scheme = AES_GCM_128_DOUBLE_NONCE_PAYLOAD_SIZE has bad size. Shold be  " 
                       << expectedSize  << " bytes, but got " << mNetworkMsg[ mNextAvialableThread ].header.totalLength << " bytes";
                mLogger.Error( logMsg.str() );

                CreateErrorMsg( OPENSSM_ESTABLISH_SESSION_FAILED_BAD_MSG, NULL, 0 );
                mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
                return OPENSSM_ESTABLISH_SESSION_FAILED_BAD_MSG;
            }                    
            break;
        }
        case NULL_ENCRYPTION:
        {
            uint32_t expectedSize = sizeof( OpenSSMMsgHeader ) + 
                                    sizeof( EstablishSessionKeysMsg ) ;
            if( mNetworkMsg[ mNextAvialableThread ].header.totalLength != expectedSize )
            {
                logMsg << "Establish session msg with scheme = NULL_ENCRYPTION has bad size. Shold be  " 
                       << expectedSize  << " bytes, but got " << mNetworkMsg[ mNextAvialableThread ].header.totalLength << " bytes";
                mLogger.Error( logMsg.str() );

                CreateErrorMsg( OPENSSM_ESTABLISH_SESSION_FAILED_BAD_MSG, NULL, 0 );
                mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
                return OPENSSM_ESTABLISH_SESSION_FAILED_BAD_MSG;
            }                    
            break;
        }

        default:
            logMsg << "Bad session key scheme " << establishSessionMsg->scheme ;
            mLogger.Error( logMsg.str() );

            CreateErrorMsg( OPENSSM_ESTABLISH_SESSION_FAILED_BAD_SCHEME, (uint8_t*)establishSessionMsg->scheme , sizeof( establishSessionMsg->scheme ) );
            mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
            return OPENSSM_ESTABLISH_SESSION_FAILED_BAD_SCHEME;
    }

    return OPENSSM_SUCCESS;
}

OpenSSMStatus OpenSSMServer::RemoteAttestation_ProcessMsg2_GetMsg3(  sgx_ra_msg2_t*  message2, 
                                                                     uint32_t        msg2_size,
                                                                     sgx_ra_msg3_t** message3, 
                                                                     uint32_t*       msg3_size)
{
    sgx_status_t  status = sgx_ra_proc_msg2(   mRemoteAttestationContext,
                                               mEnclaveID,
                                               SSM_ProcessMsg2,
                                               sgx_ra_get_msg3_trusted,
                                               message2,
                                               msg2_size,
                                               message3,
                                               msg3_size );

    if( SGX_SUCCESS != status )
    {
        ostringstream logMsg;
        logMsg << "Call sgx_ra_proc_msg2 failed. Error = 0x";
        logMsg << std::hex << status;
        mLogger.Error( logMsg.str() );

        CreateErrorMsg( OPENSSM_INIT_GET_MSG2_FAILED, (uint8_t*)&status, sizeof( status ) );
        mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
        return OPENSSM_INIT_GET_MSG2_FAILED;
    }

    // mLogger.Debug( "-----------------------Calling EcallPrintKeys" );
    // EcallPrintKeys( mEnclaveID, mRemoteAttestationContext );

    return OPENSSM_SUCCESS;
}

OpenSSMStatus OpenSSMServer::RemoteAttestation_ProcessMsg2_verifyAttestationState()
{
    if( mAttestationState != WAITING_FOR_MSG2 )
    {
        ostringstream logMsg;
        logMsg << "Service provider requesting msg3, but corrent attestation state is ";
        logMsg << mAttestationState;
        mLogger.Error( logMsg.str() );

        CreateErrorMsg( OPENSSM_INIT_GET_MSG2_CALL_INIT_RA, NULL, 0 );
        mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
        return OPENSSM_INIT_GET_MSG2_CALL_INIT_RA;
    }

    return OPENSSM_SUCCESS;
}

void OpenSSMServer::RemoteAttestation_ProcessMsg2()
{
    mLogger.Debug( __FUNCTION__ );

    if( OPENSSM_SUCCESS != RemoteAttestation_ProcessMsg2_verifyAttestationState() )
        return;

    if( OPENSSM_SUCCESS != RemoteAttestation_ProcessMsg2_verifyMsgSize() )
        return;

    sgx_ra_msg2_t *message2 = ( sgx_ra_msg2_t* )mNetworkMsg[ mNextAvialableThread ].body;
    uint32_t msg2_size      = mNetworkMsg[ mNextAvialableThread ].header.totalLength - sizeof( OpenSSMMsgHeader );
    sgx_ra_msg3_t *message3 = NULL;
    uint32_t msg3_size      = 0;
    if( OPENSSM_SUCCESS != RemoteAttestation_ProcessMsg2_GetMsg3(   message2, 
                                                                    msg2_size, 
                                                                    &message3, 
                                                                    &msg3_size ) )
        return;

    mNetworkMsg[ mNextAvialableThread ].header.totalLength  = (uint16_t)( sizeof( OpenSSMMsgHeader ) + msg3_size );
    mNetworkMsg[ mNextAvialableThread ].header.msgType      = RESPONSE_INIT_MSG3;
    memcpy( mNetworkMsg[ mNextAvialableThread ].body, message3, msg3_size );
    mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );

    free( message3 );
    mAttestationState = WAITING_FOR_SESSION_REQUEST;
}

OpenSSMStatus OpenSSMServer::EstablishSession_callEnclave(  UserID                  *userID,
                                                            uint8_t                 *remoteNonce, 
                                                            uint8_t                 *ssmNonce, 
                                                            SessionKeysScheme       keyExchangeScheme )
{
    OpenSSMStatus retVal     = OPENSSM_SUCCESS;
    sgx_status_t ecallStatus = EcallEstablishSession(   mEnclaveID,
                                                        &retVal,
                                                        &userID->userID,
                                                        keyExchangeScheme, 
                                                        remoteNonce, 
                                                        ssmNonce,
                                                        AES_GCM_128_DOUBLE_NONCE_PAYLOAD_SIZE );
    if( SGX_SUCCESS != ecallStatus )
    {
        ostringstream logMsg;
        logMsg << "SGX ERROR: Call EcallEstablishSession failed. SGX Error = 0x";
        logMsg << std::hex << ecallStatus;
        mLogger.Error( logMsg.str() );

        CreateErrorMsg( OPENSSM_ESTABLISH_SESSION_FAILED_SGX_ERROR, (uint8_t*)&ecallStatus, sizeof( ecallStatus ) );
        mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
        return OPENSSM_ESTABLISH_SESSION_FAILED_SGX_ERROR;
    }

    if( OPENSSM_SUCCESS != retVal )
    {
        ostringstream logMsg;
        logMsg << "Call EcallEstablishSession failed. OpenSSM Error = 0x";
        logMsg << std::hex << retVal;
        mLogger.Error( logMsg.str() );

        CreateErrorMsg( retVal, NULL, 0 );
        mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
        return retVal;
    }

    return OPENSSM_SUCCESS;
}

void OpenSSMServer::LogUserIDLoging( UserID* userID )
{
    ostringstream logMsg;
    logMsg << "Trying to establish session with userID = 0x";

    uint8_t *userID_as_bytes = (uint8_t*)userID;
    for( uint32_t i = 0; i < sizeof( UserID ); ++i )
        logMsg << std::setfill('0') << std::setw(2) << std::hex << (unsigned int)userID_as_bytes[ i ];

    mLogger.Info( logMsg.str() );
}

void OpenSSMServer::EstablishSession()
{
    mLogger.Debug( __FUNCTION__ );

    if( OPENSSM_SUCCESS != EstablishSession_verifyMsgSize() )
        return;

    EstablishSessionKeysMsg* establishSessionMsg = ( EstablishSessionKeysMsg* )mNetworkMsg[ mNextAvialableThread ].body;
    
    if( OPENSSM_SUCCESS != EstablishSession_verifyAttestationState( establishSessionMsg->scheme ) )
        return;
    
    uint8_t *remoteNonce = NULL;
    if( AES_GCM_128_DOUBLE_NONCE == establishSessionMsg->scheme )
        remoteNonce = establishSessionMsg->extraData;

    uint8_t ssmNonce[ AES_GCM_128_DOUBLE_NONCE_PAYLOAD_SIZE ] = {0};

    LogUserIDLoging( &establishSessionMsg->userID );
    if( OPENSSM_SUCCESS != EstablishSession_callEnclave( &establishSessionMsg->userID,
                                                         remoteNonce, 
                                                         ssmNonce, 
                                                         establishSessionMsg->scheme ) )
        return;
    
    mNetworkMsg[ mNextAvialableThread ].header.msgType      = RESPONSE_ESTABLISH_SESSION;
    mNetworkMsg[ mNextAvialableThread ].header.totalLength  = (uint16_t)(   sizeof( OpenSSMMsgHeader             ) + 
                                                    sizeof( EstablishSessionKeysResponse ) ); 
    EstablishSessionKeysResponse* establishSessionResponse  = ( EstablishSessionKeysResponse* )mNetworkMsg[ mNextAvialableThread ].body;

    if( AES_GCM_128_DOUBLE_NONCE == establishSessionMsg->scheme )
        mNetworkMsg[ mNextAvialableThread ].header.totalLength += AES_GCM_128_DOUBLE_NONCE_PAYLOAD_SIZE;
    memcpy( establishSessionResponse->data, ssmNonce, AES_GCM_128_DOUBLE_NONCE_PAYLOAD_SIZE );

    mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );

    if( KEY_SCHEME_NULL_ENCRYPTION != establishSessionMsg->scheme )
        mAttestationState = SESSION_KEYS_EXCHANGED;
}

OpenSSMStatus OpenSSMServer::HandleEncryptedMsg_verifyAttestationState( SessionEncryptionScheme scheme )
{
    if( mAttestationState == SESSION_KEYS_EXCHANGED || 
        mAttestationState == SESSION_ACTIVE )
        return OPENSSM_SUCCESS;

    if( NULL_ENCRYPTION == scheme ) //We don't care about attestation state if the session is not secured
        return OPENSSM_SUCCESS;
  
    ostringstream logMsg;
    logMsg << "Got encrypted message, but current state is: ";
    logMsg << mAttestationState;
    mLogger.Error( logMsg.str() );

    CreateErrorMsg( OPENSSM_ENCRYPTED_MSG_FAILED_BAD_STATE, ( uint8_t* )&mAttestationState, sizeof( mAttestationState ) );
    mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
    return OPENSSM_ENCRYPTED_MSG_FAILED_BAD_STATE;
}

OpenSSMStatus OpenSSMServer::HandleEncryptedMsg_verifyMsgSize()
{
    ostringstream logMsg;
    uint32_t minimumExpectedSize =  sizeof( OpenSSMMsgHeader ) + 
                                    sizeof( EncryptedMsg )     + 
                                    sizeof( SecureMsgType );
    if( mNetworkMsg[ mNextAvialableThread ].header.totalLength < minimumExpectedSize )
    {
        logMsg << "Encrypted msg is too small. Shold be at least " << minimumExpectedSize ;
        logMsg << " bytes, but got " << mNetworkMsg[ mNextAvialableThread ].header.totalLength << " bytes";
        mLogger.Error( logMsg.str() );

        CreateErrorMsg( OPENSSM_ENCRYPTED_MSG_FAILED_BAD_MSG, NULL, 0 );
        mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
        return OPENSSM_ENCRYPTED_MSG_FAILED_BAD_MSG;
    }

    EncryptedMsg *encryptedMsg = ( EncryptedMsg* )mNetworkMsg[ mNextAvialableThread ].body;
    if( encryptedMsg->encryptionScheme != AES_GCM_128 &&
        encryptedMsg->encryptionScheme != NULL_ENCRYPTION )
    {
        logMsg << "Encrypted msg scheme is wrong: " << encryptedMsg->encryptionScheme;
        mLogger.Error( logMsg.str() );

        CreateErrorMsg( OPENSSM_ENCRYPTED_MSG_FAILED_BAD_SCHEME, NULL, 0 );
        mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
        return OPENSSM_ENCRYPTED_MSG_FAILED_BAD_SCHEME;
    }

    size_t expectedCipherSize = mNetworkMsg[ mNextAvialableThread ].header.totalLength - sizeof( OpenSSMMsgHeader ) - sizeof( EncryptedMsg );
    if( encryptedMsg->cipherSize != expectedCipherSize )
    {
        logMsg << "encryptedMsg->cipherSize shold be: " << expectedCipherSize << " bytes "
               << "but instead got: " << encryptedMsg->cipherSize << " bytes." ;
        mLogger.Error( logMsg.str() );

        CreateErrorMsg( OPENSSM_ENCRYPTED_MSG_FAILED_BAD_MSG, NULL, 0 );
        mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
        return OPENSSM_ENCRYPTED_MSG_FAILED_BAD_MSG;
    }

    return OPENSSM_SUCCESS;
}

// typedef struct ms_EcallHandleEncryptedMsg_t {
//     OpenSSMStatus ms_retval;
//     EncryptedMsg* ms_encryptedMsg;
//     size_t ms_maxResponseSize;
// } ms_EcallHandleEncryptedMsg_t;

void HotEcallHandleEncryptedMsg( HotCall* hotCall, OpenSSMStatus* retval, EncryptedMsg* encryptedMsg, size_t maxResponseSize)
{
    ms_EcallHandleEncryptedMsg_t ms;
    ms.ms_encryptedMsg = encryptedMsg;
    ms.ms_maxResponseSize = maxResponseSize;

    uint16_t requestedCallID_HandleEncryptedMsg = 0;
    HotCall_requestCall( hotCall, requestedCallID_HandleEncryptedMsg, &ms );

    *retval = ms.ms_retval;
}

void OpenSSMServer::HotEcallHandleEncryptedMsg_dontBlock( HotCall* hotCall, EncryptedMsg* encryptedMsg, size_t maxResponseSize)
{
    ms_EcallHandleEncryptedMsg_t *ms = &mHotCallsData[ mNextAvialableThread ];
    ms->ms_encryptedMsg = encryptedMsg;
    ms->ms_maxResponseSize = maxResponseSize;

    uint16_t requestedCallID_HandleEncryptedMsg = 0;
    // printf("###### %s: %d; ms = %p\n", __FUNCTION__, __LINE__, ms );
    HotCall_requestCall_dontBlock( hotCall, requestedCallID_HandleEncryptedMsg, ms );

    // *retval = ms.ms_retval;
}

OpenSSMStatus OpenSSMServer::HotEcallHandleEncryptedMsg_waitForResponse( HotCall* hotCall )
{
    ms_EcallHandleEncryptedMsg_t *ms = &mHotCallsData[ mNextThreadToWaitFor ];
    HotCall_requestCall_waitForResponse( hotCall );

    return ms->ms_retval;
}

OpenSSMStatus OpenSSMServer::HandleEncryptedMsg_callEnclave()
{
    const size_t MAX_RESPONSE_SIZE = MSG_BUFFER_SIZE - sizeof( OpenSSMMsgHeader ) - sizeof( EncryptedMsg );

    EncryptedMsg *encryptedMsg  = ( EncryptedMsg* )mNetworkMsg[ mNextAvialableThread ].body;
    OpenSSMStatus retVal        = OPENSSM_SUCCESS;

    if( mHotCallDispatcher[ mNextAvialableThread ].hotCall != NULL )
    {
        HotEcallHandleEncryptedMsg( mHotCallDispatcher[ mNextAvialableThread ].hotCall, &retVal, encryptedMsg, MAX_RESPONSE_SIZE );
    }
    else {
        
        sgx_status_t ecallStatus = EcallHandleEncryptedMsg( mEnclaveID, &retVal, encryptedMsg, MAX_RESPONSE_SIZE );
        
        if( SGX_SUCCESS != ecallStatus )
        {
            ostringstream logMsg;
            logMsg << "SGX Error: Call EcallHandleEncryptedMsg fail. Error = 0x";
            logMsg << std::hex << ecallStatus;
            mLogger.Error( logMsg.str() );

            CreateErrorMsg( OPENSSM_ENCRYPTED_MSG_FAILED_UNEXPECTED, (uint8_t*)&ecallStatus, sizeof( ecallStatus ) );
            mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
            return OPENSSM_ENCRYPTED_MSG_FAILED_UNEXPECTED;
        }
    }

    if( OPENSSM_SUCCESS != retVal )
    {
        ostringstream logMsg;
        logMsg << "Call EcallHandleEncryptedMsg failed. OpenSSM Error = 0x";
        logMsg << std::hex << retVal;
        mLogger.Error( logMsg.str() );

        CreateErrorMsg( retVal, NULL, 0 );
        mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
        return retVal;
    }

    return OPENSSM_SUCCESS;
}

OpenSSMStatus OpenSSMServer::HandleEncryptedMsg_callEnclave_dontBlock()
{
    const size_t MAX_RESPONSE_SIZE = MSG_BUFFER_SIZE - sizeof( OpenSSMMsgHeader ) - sizeof( EncryptedMsg );

    // printf("################# Dispatching mNextAvialableThread = %d (mNextThreadToWaitFor = %d)\n", mNextAvialableThread, mNextThreadToWaitFor );

    EncryptedMsg *encryptedMsg  = ( EncryptedMsg* )mNetworkMsg[ mNextAvialableThread ].body;
    OpenSSMStatus retVal        = OPENSSM_SUCCESS;

    // printf("############# %s: %d; debugTable = ", __FUNCTION__, __LINE__ );
    // for( int threadIdx = 0; threadIdx < NUM_WORKER_THREADS; threadIdx++ )
    //     printf("%d,", debugTable[ threadIdx ] );
    // printf("\n");
    // if( debugTable[ mNextAvialableThread ] == true ){
    //         printf("@@@@@@@@@@@@@@@@@@@ %s: %d\n", __FUNCTION__, __LINE__ );
    //         exit(42);
    //     }

    if( mHotCallDispatcher[ mNextAvialableThread ].hotCall != NULL )
    {
        debugTable[ mNextAvialableThread ] = true;
        // HotEcallHandleEncryptedMsg( mHotCallDispatcher[ mNextAvialableThread ].hotCall, &retVal, encryptedMsg, MAX_RESPONSE_SIZE );
        HotEcallHandleEncryptedMsg_dontBlock( mHotCallDispatcher[ mNextAvialableThread ].hotCall, encryptedMsg, MAX_RESPONSE_SIZE );

        if( mNextThreadToWaitFor == -1 )
            mNextThreadToWaitFor = mNextAvialableThread;
        
        mNextAvialableThread = ( mNextAvialableThread + 1 ) % NUM_WORKER_THREADS;
        if( mNextAvialableThread == mNextThreadToWaitFor )
            mNextAvialableThread = -1;
        
        // printf("################# After dispatching work: mNextAvialableThread = %d (mNextThreadToWaitFor = %d)\n", mNextAvialableThread, mNextThreadToWaitFor );

        return OPENSSM_SUCCESS;
    }
    else {
        printf("@@@@@@@@@@@@@@@ %s: %d; SHOULD NEVER GET HERE\n", __FUNCTION__, __LINE__ );
        sgx_status_t ecallStatus = EcallHandleEncryptedMsg( mEnclaveID, &retVal, encryptedMsg, MAX_RESPONSE_SIZE );
        
        if( SGX_SUCCESS != ecallStatus )
        {
            ostringstream logMsg;
            logMsg << "SGX Error: Call EcallHandleEncryptedMsg fail. Error = 0x";
            logMsg << std::hex << ecallStatus;
            mLogger.Error( logMsg.str() );

            CreateErrorMsg( OPENSSM_ENCRYPTED_MSG_FAILED_UNEXPECTED, (uint8_t*)&ecallStatus, sizeof( ecallStatus ) );
            mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
            return OPENSSM_ENCRYPTED_MSG_FAILED_UNEXPECTED;
        }
    }

    if( OPENSSM_SUCCESS != retVal )
    {
        ostringstream logMsg;
        logMsg << "Call EcallHandleEncryptedMsg failed. OpenSSM Error = 0x";
        logMsg << std::hex << retVal;
        mLogger.Error( logMsg.str() );

        CreateErrorMsg( retVal, NULL, 0 );
        mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
        return retVal;
    }

    return OPENSSM_SUCCESS;
}


OpenSSMStatus OpenSSMServer::SaveEchangedKeysToPermenantStorage_callEnclave( uint8_t* sealedMasterSecrets, uint32_t sealedDataSize )
{
    OpenSSMStatus retVal     = OPENSSM_SUCCESS;
    sgx_status_t ecallStatus = EcallSealMasterSecrets( mEnclaveID, &retVal, sealedMasterSecrets, sealedDataSize );
    if( SGX_SUCCESS != ecallStatus )
    {
        ostringstream logMsg;
        logMsg << "SGX Error: Call EcallSealMAsterSecrets failed. Error = 0x";
        logMsg << std::hex << ecallStatus;
        mLogger.Error( logMsg.str() );

        CreateErrorMsg( OPENSSM_CANT_SEAL_MASTER_SECRETS, (uint8_t*)&ecallStatus, sizeof( ecallStatus ) );
        mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
        return OPENSSM_CANT_SEAL_MASTER_SECRETS;
    }

    if( OPENSSM_SUCCESS != retVal )
    {
        ostringstream logMsg;
        logMsg << "Call EcallSealMAsterSecrets failed. OpenSSM Error = 0x";
        logMsg << std::hex << retVal;
        mLogger.Error( logMsg.str() );

        CreateErrorMsg( retVal, NULL, 0 );
        mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
        return retVal;
    }

    return OPENSSM_SUCCESS;
}

OpenSSMStatus OpenSSMServer::SaveEchangedKeysToPermenantStorage_getSealedDataSize( uint32_t *sealedDataSize )
{
    sgx_status_t ecallStatus = EcallSealMasterSecrets_getSealedDataSize( mEnclaveID, sealedDataSize );
    if( SGX_SUCCESS != ecallStatus )
    {
        ostringstream logMsg;
        logMsg << "SGX Error: Call EcallSealMAsterSecrets failed. Error = 0x";
        logMsg << std::hex << ecallStatus;
        mLogger.Error( logMsg.str() );

        CreateErrorMsg( OPENSSM_UNEXPECTED, (uint8_t*)&ecallStatus, sizeof( ecallStatus ) );
        mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
        return OPENSSM_UNEXPECTED;
    }

    return OPENSSM_SUCCESS;
}

OpenSSMStatus OpenSSMServer::SaveEchangedKeysToPermenantStorage()
{
    mLogger.Debug( __FUNCTION__ );

    uint32_t sealedDataSize = 0;
    if( OPENSSM_SUCCESS != SaveEchangedKeysToPermenantStorage_getSealedDataSize( &sealedDataSize ) )
        return OPENSSM_UNEXPECTED;

    uint8_t sealedMasterSecrets[ sealedDataSize ];

    OpenSSMStatus ret = SaveEchangedKeysToPermenantStorage_callEnclave( sealedMasterSecrets, sealedDataSize );
    if( OPENSSM_SUCCESS != ret )
        return ret;

    ostringstream logMsg;
    logMsg << "Sealing master keys to file: " << SEALED_MASTER_KEYS_FILE_PATH ;
    mLogger.Info( logMsg.str() );
    
    ofstream sealedMasterKeysFile;
    sealedMasterKeysFile.open( SEALED_MASTER_KEYS_FILE_PATH , ios::out | ios::binary );
    sealedMasterKeysFile.write( (char*) sealedMasterSecrets, sealedDataSize );    
    sealedMasterKeysFile.close();

    return OPENSSM_SUCCESS;
}


uint32_t OcallSaveAllowedUsers( uint8_t* sealedAllowedUsres, uint32_t sealedDataSize )
{
    ostringstream logMsg;
    logMsg << "Sealing allowed users to file: " << SEALED_ALLOWED_USERS_FILE_PATH  ;
    ocallLogger.Info( logMsg.str() );
    
    ofstream sealedMasterKeysFile;
    sealedMasterKeysFile.open( SEALED_ALLOWED_USERS_FILE_PATH , ios::out | ios::binary );
    sealedMasterKeysFile.write( (char*) sealedAllowedUsres, sealedDataSize );    
    sealedMasterKeysFile.close();

    return ( uint32_t )OPENSSM_SUCCESS;   
}

void OpenSSMServer::HandleReset()
{
    mLogger.Debug( __FUNCTION__ );  
    
    mAttestationState = WAITING_FOR_SESSION_REQUEST;
    mNetworkMsg[ mNextAvialableThread ].header.msgType      = RESPONSE_RESET;
    mNetworkMsg[ mNextAvialableThread ].header.totalLength  = (uint16_t)( sizeof( OpenSSMMsgHeader ) );
    
    mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
    mNetworkManager.CloseConnectionAndWaitForNextOne();
}

void OpenSSMServer::HandleSync()
{
    mLogger.Debug( __FUNCTION__ );  
    
    mNetworkMsg[ mNextAvialableThread ].header.msgType      = RESPONSE_SYNC;
    mNetworkMsg[ mNextAvialableThread ].header.totalLength  = (uint16_t)( sizeof( OpenSSMMsgHeader ) + sizeof( SyncResponse ) );
    
    SyncResponse *syncResponse = ( SyncResponse* )mNetworkMsg[ mNextAvialableThread ].body;

    sgx_status_t ecallStatus = EcallGetSync( mEnclaveID, &syncResponse->lastSessionMsgCounter );
    if( SGX_SUCCESS != ecallStatus )
    {
        ostringstream logMsg;
        logMsg << "SGX Error: Call EcallGetSync fail. Error = 0x";
        logMsg << std::hex << ecallStatus;
        mLogger.Error( logMsg.str() );

        CreateErrorMsg( OPENSSM_UNEXPECTED, (uint8_t*)&ecallStatus, sizeof( ecallStatus ) );
        mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
        return;
    }

    mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
}
void OpenSSMServer::HandleEncryptedMsg()
{
    mLogger.Debug( __FUNCTION__ );

    if( OPENSSM_SUCCESS != HandleEncryptedMsg_verifyMsgSize() )
        return;



    // if( NUM_WORKER_THREADS > 1 ){
        //Need to send the request to the enclave, don't wait for answer
        if( OPENSSM_SUCCESS != HandleEncryptedMsg_callEnclave_dontBlock() )
            return;
    // }
    // else if( OPENSSM_SUCCESS != HandleEncryptedMsg_callEnclave() ) //Will put response in encryptedMsg in mNetworkMsg[ mNextAvialableThread ].body
    //     return;

    if( mAttestationState == SESSION_KEYS_EXCHANGED )
        // If we got here, it means session keys have been exchanged succeffully, and message was decrypted successfully
        // We should seal the master secrets, so next time we can skip remote attestation handshake
            if( OPENSSM_SUCCESS != SaveEchangedKeysToPermenantStorage() )
                return;

    // if( NUM_WORKER_THREADS > 1 )
    //     return; //Don't need to get result yet

    // EncryptedMsg            *encryptedMsg       = ( EncryptedMsg* )mNetworkMsg[ mNextAvialableThread ].body;
    // SessionEncryptionScheme encryptionScheme    = ( SessionEncryptionScheme ) encryptedMsg->encryptionScheme;
    // if( OPENSSM_SUCCESS != HandleEncryptedMsg_verifyAttestationState( encryptionScheme ) )
    //     return;


    // mNetworkMsg[ mNextAvialableThread ].header.msgType      = RESPONSE_ENCRYPTED_MSG;
    // mNetworkMsg[ mNextAvialableThread ].header.totalLength  = (uint16_t)(   sizeof( OpenSSMMsgHeader )  + 
    //                                                 sizeof( EncryptedMsg )      +
    //                                                 encryptedMsg->cipherSize );
    // mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );

    // mAttestationState = SESSION_ACTIVE;
}

void OpenSSMServer::DispatchMessageFromNetwork()
{
    // uint8_t currentThreadIdx = ( mPreviousThreadIdx + 1 ) % NUM_WORKER_THREADS;
    mNetworkManager.GetNextMessage( mNetworkMsg[ mNextAvialableThread ] );

    ostringstream logMsg;
    logMsg << "Got message: " << mNetworkMsg[ mNextAvialableThread ].header.msgType ;
    mLogger.Debug( logMsg.str() );
    
    switch( mNetworkMsg[ mNextAvialableThread ].header.msgType )
    {
        case REQUEST_GET_VERSION:
            mLogger.Debug( "Got REQUEST_GET_VERSION!" );
            SendVersionMsg();
            break;

        case REQUEST_INIT_START:
            mLogger.Debug( "Got REQUEST_INIT_START!" );
            //TODO: verify SSM is not already initialized. If ok then
            RemoteAttestation_Start();
            break;

        case REQUEST_INIT_MSG2:
            mLogger.Debug( "Got REQUEST_INIT_MSG2!" );
            RemoteAttestation_ProcessMsg2();
            break;

        case REQUEST_ESTABLISH_SESSION:
            mLogger.Debug( "Got REQUEST_ESTABLISH_SESSION!" );
            EstablishSession();
            break;

        case REQUEST_ENCRYPTED_MSG:
            mLogger.Debug( "Got REQUEST_ENCRYPTED_MSG!" );
            HandleEncryptedMsg();
            break;

        case REQUEST_RESET:
            HandleReset();
            break;

        case REQUEST_SYNC:
            HandleSync();
            break;

        case RESPONSE_GET_VERSION:
        case RESPONSE_INIT_MSG1:
        case RESPONSE_INIT_MSG3:
            //TODO: implement. Should never get this message, but we have to implement
            //      to prevent warning
            // break;

        default:
            ostringstream logMsg;
            logMsg << "Unknown message: " << mNetworkMsg[ mNextAvialableThread ].header.msgType ;
            mLogger.Error( logMsg.str() );
            CreateErrorMsg( OPENSSM_UNKNOWN_MESSAGE_TYPE, (uint8_t*)&mNetworkMsg[ mNextAvialableThread ].header.msgType, sizeof( mNetworkMsg[ mNextAvialableThread ].header.msgType ) );
            mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
            //TODO: handle unknown messages
    }
}

OpenSSMStatus ReadFromFile( string filePath, uint8_t* buffer, uint32_t len )
{
    FILE *file = NULL;
    file       = fopen( filePath.c_str() , "rb" );  
    
    if( NULL == file ) {
        return OPENSSM_UNEXPECTED;
    }

    const size_t READ_BYTES = 1;
    size_t bytesRead = fread(   buffer,
                                READ_BYTES,
                                len,
                                file ); 
    if( len != bytesRead ) {
        fclose( file );
        return OPENSSM_UNEXPECTED;
    }

    fclose( file );
    return OPENSSM_SUCCESS;
}

OpenSSMStatus OpenSSMServer::ReadSealedMasterKeysFromFile( uint8_t *sealedMasterSecrets, uint32_t sealedDataSize )
{
    ostringstream logMsg;
    
    FILE *sealedMasterKeysFile = NULL;
    sealedMasterKeysFile       = fopen( SEALED_MASTER_KEYS_FILE_PATH , "rb" );  
    if( NULL == sealedMasterKeysFile )
    {
        logMsg  << "Failed openning sealed master keys file " << SEALED_MASTER_KEYS_FILE_PATH 
                << ": " << strerror( errno ) << ". Moving on.";
        mLogger.Info( logMsg.str() );
        return OPENSSM_ERROR_READING_SEALED_MASTER_KEYS;
    }

    logMsg  << "Successfully openned sealed master keys file " <<  SEALED_MASTER_KEYS_FILE_PATH;
    mLogger.Info( logMsg.str() );
    logMsg.clear();
    logMsg.str( "" );

    const size_t READ_BYTES = 1;
    size_t bytesRead = fread(   sealedMasterSecrets,
                                READ_BYTES,
                                sealedDataSize,
                                sealedMasterKeysFile ); 
    if( sealedDataSize != bytesRead ){
        logMsg  << "Failed reading sealed master keys file " << SEALED_MASTER_KEYS_FILE_PATH
                << ". Expected to read " << sealedDataSize << " bytes, but read only " 
                << bytesRead << " bytes. Moving on.";
        mLogger.Error( logMsg.str() );
        fclose( sealedMasterKeysFile );
        return OPENSSM_ERROR_READING_SEALED_MASTER_KEYS;
    }
    fclose( sealedMasterKeysFile );

    return OPENSSM_SUCCESS;
}

OpenSSMStatus OpenSSMServer::LoadMasterKeyys_callEnclave( uint8_t *sealedMasterSecrets, uint32_t sealedDataSize )
{
    ostringstream logMsg;
    OpenSSMStatus retVal     = OPENSSM_SUCCESS;
    sgx_status_t ecallStatus = EcallUnsealMasterSecrets( mEnclaveID, &retVal, sealedMasterSecrets, sealedDataSize );
    if( SGX_SUCCESS != ecallStatus )
    {
        logMsg << "SGX Error: Call EcallUnsealMasterSecrets failed. Error = 0x";
        logMsg << std::hex << ecallStatus;
        mLogger.Error( logMsg.str() );
        CreateErrorMsg( OPENSSM_CANT_UNSEAL_MASTER_SECRETS, (uint8_t*)&ecallStatus, sizeof( ecallStatus ) );
        mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
        return OPENSSM_CANT_UNSEAL_MASTER_SECRETS;
    }
    
    if( OPENSSM_SUCCESS != retVal )
    {
        logMsg << "Call EcallUnsealMasterSecrets failed. OpenSSM Error = 0x";
        logMsg << std::hex << retVal;
        mLogger.Error( logMsg.str() );

        CreateErrorMsg( retVal, NULL, 0 );
        mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
        return retVal;
    }
    
    mAttestationState = WAITING_FOR_SESSION_REQUEST;
    mLogger.Info( "Successfully unsealed and loaded master keys." );
    
    return OPENSSM_SUCCESS;
}

OpenSSMStatus OpenSSMServer::LoadAllowedUsers_callEnclave( uint8_t *sealedAllowedUsers, uint32_t sealedDataSize )
{
    ostringstream logMsg;
    OpenSSMStatus retVal     = OPENSSM_SUCCESS;
    sgx_status_t ecallStatus = EcallUnsealAllowedUsers( mEnclaveID, &retVal, sealedAllowedUsers, sealedDataSize );
    if( SGX_SUCCESS != ecallStatus )
    {
        logMsg << "SGX Error: Call EcallUnsealAllowedUsers failed. Error = 0x";
        logMsg << std::hex << ecallStatus;
        mLogger.Error( logMsg.str() );
        CreateErrorMsg( OPENSSM_CANT_UNSEAL_MASTER_SECRETS, (uint8_t*)&ecallStatus, sizeof( ecallStatus ) );
        mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
        return OPENSSM_CANT_UNSEAL_MASTER_SECRETS;
    }
    
    if( OPENSSM_SUCCESS != retVal )
    {
        logMsg << "Call EcallUnsealAllowedUsers failed. OpenSSM Error = 0x";
        logMsg << std::hex << retVal;
        mLogger.Error( logMsg.str() );

        CreateErrorMsg( retVal, NULL, 0 );
        mNetworkManager.SendMessage( mNetworkMsg[ mNextAvialableThread ] );
        return retVal;
    }
    
    mAttestationState = WAITING_FOR_SESSION_REQUEST;
    mLogger.Info( "Successfully unsealed and allowed users." );
    
    return OPENSSM_SUCCESS;
}

uint32_t GetFileSize( string filePath )
{
    struct stat st; 

    if( stat( filePath.c_str(), &st) == 0 )
        return st.st_size;

    return 0; 
}

uint32_t GetMasterKeysFileSize()
{
    return GetFileSize( SEALED_MASTER_KEYS_FILE_PATH );
}

void OpenSSMServer::TryLoadingMasterKeys()
{
    const uint32_t sealedDataSize = GetMasterKeysFileSize();
    uint8_t sealedMasterSecrets[ sealedDataSize ];
    
    if( OPENSSM_SUCCESS != ReadSealedMasterKeysFromFile( sealedMasterSecrets, sealedDataSize ) )
        return ;
    
    if( OPENSSM_SUCCESS != LoadMasterKeyys_callEnclave( sealedMasterSecrets, sealedDataSize ) )
        return;
}

void OpenSSMServer::TryLoadingAllowedUsers()
{
    ostringstream logMsg;
    std::ifstream file( SEALED_ALLOWED_USERS_FILE_PATH, std::ios::binary | std::ios::ate);
    if( file.is_open() ) {
        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        std::vector<char> buffer(size);
        if ( file.read( buffer.data(), size ) )
        {
            LoadAllowedUsers_callEnclave( (uint8_t*)&buffer[ 0 ], size );
            logMsg  << "Successfully loaded sealed allowed users from file " << SEALED_ALLOWED_USERS_FILE_PATH;
            mLogger.Info( logMsg.str() );
            return;
        }
    }

    logMsg  << "Failed openning sealed allowed users file " << SEALED_ALLOWED_USERS_FILE_PATH 
            << ": " << strerror( errno ) << ". Moving on.";
    mLogger.Info( logMsg.str() );
}

void* EnclaveResponderThread( void* hotEcallDispatcherAsVoidP )
{
    //To be started in a new thread
    HotCallDispatcher *hotCallDispatcher = (HotCallDispatcher*)hotEcallDispatcherAsVoidP;
    EcallStartResponder( hotCallDispatcher->enclaveID, hotCallDispatcher->hotCall );

    return NULL;
}


void OpenSSMServer::Start( int port )
{
    if( mHotCallDispatcher[ 0 ].hotCall != NULL ) //Are HotCalls enabled?
    {
        for( uint8_t threadIdx = 0; threadIdx < NUM_WORKER_THREADS; threadIdx++ )
        {
            mLogger.Info( "Starting HotCalls thread");
            pthread_create( &mHotCallDispatcher[ threadIdx ].hotCall->responderThread, 
                            NULL, 
                            EnclaveResponderThread, 
                            (void*)&mHotCallDispatcher[ threadIdx ] );
        }
    }

    mNetworkManager.Start( port );

    TryLoadingMasterKeys();
    TryLoadingAllowedUsers();

    while( true )
    {
        // if( NUM_WORKER_THREADS == 1 )
        //     DispatchMessageFromNetwork();
        // else 
        {
            if( IsWorkerAvailable() && mNetworkManager.IsMsgPending() )
                DispatchMessageFromNetwork();
            else if ( mNextThreadToWaitFor != -1 )
                WaitForWorkerToFinish();
        }
    }
}

bool OpenSSMServer::IsWorkerAvailable()
{
    if( -1 == mNextAvialableThread  )
        return false;

    return true;
}

void OpenSSMServer::WaitForWorkerToFinish()
{
    // printf("############# waiting for thread %d (mNextAvialableThread = %d)\n", mNextThreadToWaitFor, mNextAvialableThread );

    EncryptedMsg            *encryptedMsg       = ( EncryptedMsg* )mNetworkMsg[ mNextThreadToWaitFor ].body;
    
    /* OpenSSMStatus retVal=  */
    // printf("############# %s: %d; debugTable = ", __FUNCTION__, __LINE__ );
    // for( int threadIdx = 0; threadIdx < NUM_WORKER_THREADS; threadIdx++ )
    //     printf("%d,", debugTable[ threadIdx ] );
    // printf("\n");
    // if( debugTable[ mNextThreadToWaitFor ] == false )
    //     printf("@@@@@@@@@@@@@@@@@@@ %s: %d\n", __FUNCTION__, __LINE__ );

    HotEcallHandleEncryptedMsg_waitForResponse(  mHotCallDispatcher[ mNextThreadToWaitFor ].hotCall );
    debugTable[ mNextThreadToWaitFor ] = false;
    SessionEncryptionScheme encryptionScheme    = ( SessionEncryptionScheme ) encryptedMsg->encryptionScheme;
    if( OPENSSM_SUCCESS != HandleEncryptedMsg_verifyAttestationState( encryptionScheme ) )
        return;

    mNetworkMsg[ mNextThreadToWaitFor ].header.msgType      = RESPONSE_ENCRYPTED_MSG;
    mNetworkMsg[ mNextThreadToWaitFor ].header.totalLength  = (uint16_t)(   sizeof( OpenSSMMsgHeader )  + 
                                                                sizeof( EncryptedMsg )      +
                                                                encryptedMsg->cipherSize );
    mNetworkManager.SendMessage( mNetworkMsg[ mNextThreadToWaitFor ] );

    // mNextThreadToWaitFor = ( mNextThreadToWaitFor + 1 ) % NUM_WORKER_THREADS;



    if( mNextAvialableThread == -1 )
        mNextAvialableThread = mNextThreadToWaitFor;
    
    mNextThreadToWaitFor = ( mNextThreadToWaitFor + 1 ) % NUM_WORKER_THREADS;
    if( mNextAvialableThread == mNextThreadToWaitFor )
        mNextThreadToWaitFor = -1;

    // printf("############# %s: %d; debugTable = ", __FUNCTION__, __LINE__ );
    // for( int threadIdx = 0; threadIdx < NUM_WORKER_THREADS; threadIdx++ )
    //     printf("%d,", debugTable[ threadIdx ] );
    // printf("\n");
    // printf("############## After waiting: mNextThreadToWaitFor to %d ( mNextAvialableThread = %d)\n", mNextThreadToWaitFor, mNextAvialableThread ); 

    mAttestationState = SESSION_ACTIVE;
}



/* Check error conditions for loading enclave */
void OpenSSMServer::PrintSGXErrorMessage(sgx_status_t ret) const
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

bool IsDirectoryExists( string path )
{
    struct stat st = {0};

    return ! (stat(path.c_str(), &st) == -1);
}

void EnsureDirExists( string dirName, Logger& logger )
{
    if( ! IsDirectoryExists( dirName )  ) {
        ostringstream logMsg;
        logMsg << "Creating directory " << dirName;
        logger.Info( logMsg.str() );

        mkdir( dirName.c_str(), 0700);
    }
}



uint32_t ocall_store_key_on_disk(  uint64_t keyHandle, 
                                   uint8_t* sealedKey,
                                   uint32_t len )
{
    EnsureDirExists( KEYS_DIRECTORY, ocallLogger );
    
    ostringstream keyFilePath;
    keyFilePath << KEYS_DIRECTORY << "/"
                << std::setfill('0') << std::setw( sizeof( keyHandle ) * 2 ) << std::hex
                << keyHandle << ".key";

    ostringstream logMsg;
    logMsg << "Storing key to file: " << keyFilePath.str();
    ocallLogger.Info( logMsg.str() );
    
    ofstream keyFile;
    keyFile.open( keyFilePath.str(), ios::out | ios::binary );
    keyFile.write( (char*) sealedKey, len );    
    keyFile.close();

    return OPENSSM_SUCCESS;
}

uint32_t ocall_read_key_from_disk(  uint64_t keyHandle, 
                                    uint8_t *sealedKey,
                                    uint32_t len  )
{
    uint32_t CANT_READ = 0;
    ostringstream keyFilePath;
    keyFilePath << KEYS_DIRECTORY << "/"
                << std::setfill('0') << std::setw( sizeof( keyHandle ) * 2 ) << std::hex
                << keyHandle << ".key";

    uint32_t fileSize = GetFileSize( keyFilePath.str() );
    if( 0 == fileSize) {
        ostringstream logMsg;
        logMsg << "Error getting file size for " << keyFilePath.str();
        ocallLogger.Error( logMsg.str() );
        return CANT_READ;
    }

    if( OPENSSM_SUCCESS != ReadFromFile( keyFilePath.str(), sealedKey, fileSize ) ){
        ostringstream logMsg;
        logMsg << "Error reading key from " << keyFilePath.str();
        ocallLogger.Error( logMsg.str() );  
        return CANT_READ; 
    }

    printf("Read key from file\n");
    return fileSize;
}

