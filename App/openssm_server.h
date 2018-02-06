#ifndef __OPENSSM_SERVER_H
#define __OPENSSM_SERVER_H	

#include "sgx_eid.h"     	  // sgx_enclave_id_t 
#include "sgx_error.h"        // sgx_status_t 
#include "sgx_key_exchange.h" // sgx_ra_msg1_t
#include "../include/openssm_error.h"
#include "../include/hot_calls.h"
// #include "../include/common.h"
#include "../Enclave/openssm_enclave.h"
#include "network_manager.h"

#include "logger.h"




#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

# define TOKEN_FILENAME   "enclave.token"
# define ENCLAVE_FILENAME "enclave.signed.so"



extern sgx_enclave_id_t global_eid;  



#define OPEN_SSM_SERVER_VERSION "0.0.1"

typedef struct ms_EcallHandleEncryptedMsg_t {
    OpenSSMStatus ms_retval;
    EncryptedMsg* ms_encryptedMsg;
    size_t ms_maxResponseSize;
} ms_EcallHandleEncryptedMsg_t;

typedef enum : uint16_t
{
   WAITING_FOR_SESSION_REQUEST,
   WAITING_FOR_MSG2,
   SESSION_KEYS_EXCHANGED,
   SESSION_ACTIVE
} AttestationState;



class OpenSSMServer
{
public:
	//members:
	sgx_enclave_id_t mEnclaveID;
	sgx_ra_context_t mRemoteAttestationContext;
	
	//methods:
	OpenSSMServer( NetworkManager &networkManager, bool useHotCalls = true );
	~OpenSSMServer();

	const char * Version 			() const;
	const char * EnclaveVersion 	();

	OpenSSMStatus InitEnclave		();
	OpenSSMStatus DestroyEnclave	();

	void Start						( int port );
	void DispatchMessageFromNetwork ();
	void PrintSGXErrorMessage 		(sgx_status_t ret) const;


private:
    bool    mEnclaveWasInitialized;
    char    mEnclaveVersion[ ENCLAVE_VERSION_LENGTH ];
    Logger  mLogger;

    NetworkManager 		 &mNetworkManager;
    OpenSSMMsg 		 	   mNetworkMsg[ NUM_WORKER_THREADS ];
    AttestationState 	 mAttestationState;
    HotCallDispatcher  mHotCallDispatcher[ NUM_WORKER_THREADS ];

    ms_EcallHandleEncryptedMsg_t mHotCallsData[ NUM_WORKER_THREADS ];

    int mNextAvialableThread;
    int mNextThreadToWaitFor;


    void SendVersionMsg					        ();
    void RemoteAttestation_Start  		  ();
    void RemoteAttestation_ProcessMsg2 	();
    void EstablishSession               ();
    void HandleEncryptedMsg             ();
    void HandleReset                    ();
    void HandleSync                     ();
    void CreateErrorMsg 				( 	OpenSSMStatus 	status, 
    										uint8_t* 		extraData, 
    										size_t 			extraLength );
    void TryLoadingMasterKeys           ();
    void TryLoadingAllowedUsers         ();
    void LogUserIDLoging                ( UserID* userID );

    OpenSSMStatus RemoteAttestation_Start_verifyAttestationState ();
    OpenSSMStatus RemoteAttestation_getExtendedEPIDGroupID 	     ();
    OpenSSMStatus RemoteAttestation_EcallInitRA 			           ();
    OpenSSMStatus RemoteAttestation_GetMessage1 			           ( sgx_ra_msg1_t *message1 );
    OpenSSMStatus RemoteAttestation_ProcessMsg2_verifyAttestationState();
    OpenSSMStatus RemoteAttestation_ProcessMsg2_verifyMsgSize    ();
    OpenSSMStatus RemoteAttestation_ProcessMsg2_GetMsg3 	  (    sgx_ra_msg2_t*  message2, 
                                                                 uint32_t        msg2_size,
                                                                 sgx_ra_msg3_t** message3, 
                                                                 uint32_t*       msg3_size );
    OpenSSMStatus EstablishSession_verifyAttestationState       ( SessionKeysScheme scheme );
    OpenSSMStatus EstablishSession_verifyMsgSize                ();
    OpenSSMStatus EstablishSession_callEnclave                  ( UserID                *userID,
                                                                  uint8_t               *remoteNonce, 
                                                                  uint8_t               *ssmNonce,
                                                                  SessionKeysScheme     keyExchangeScheme );
    OpenSSMStatus HandleEncryptedMsg_verifyAttestationState     ( SessionEncryptionScheme scheme );
    OpenSSMStatus HandleEncryptedMsg_verifyMsgSize              ();
    OpenSSMStatus HandleEncryptedMsg_callEnclave                ();
    OpenSSMStatus HandleEncryptedMsg_callEnclave_dontBlock      ();

    OpenSSMStatus SaveEchangedKeysToPermenantStorage            ();
    OpenSSMStatus SaveEchangedKeysToPermenantStorage_callEnclave(   uint8_t* sealedMasterSecrets, 
                                                                    uint32_t sealedDataSize );

    OpenSSMStatus ReadSealedMasterKeysFromFile                  ( uint8_t *sealedMasterSecrets, 
                                                                  uint32_t sealedDataSize );
    OpenSSMStatus LoadMasterKeyys_callEnclave                   ( uint8_t *sealedMasterSecrets, 
                                                                  uint32_t sealedDataSize );
    OpenSSMStatus LoadAllowedUsers_callEnclave                  ( uint8_t* sealedAllowedUsres, 
                                                                  uint32_t sealedDataSize );
    OpenSSMStatus SaveEchangedKeysToPermenantStorage_getSealedDataSize
                                                                ( uint32_t *sealedDataSize );

    void          HotEcallHandleEncryptedMsg_dontBlock ( HotCall* hotCall, EncryptedMsg* encryptedMsg, size_t maxResponseSize);
    OpenSSMStatus HotEcallHandleEncryptedMsg_waitForResponse( HotCall* hotCall );
    
    bool          IsWorkerAvailable();
    void          WaitForWorkerToFinish();


};

#endif