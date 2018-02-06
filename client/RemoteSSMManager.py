import sys
import unittest
import subprocess
import time
import socket
import fcntl
import logging
import os
import struct 
import errno
import pprint 
import pickle
import base64
import statistics

sys.path.insert( 0, "../tlibcrypto_wrapper/")
sys.path.insert( 0, "../libressl_wrapper/")

from sgx_crypto_wrapper            import SGXCryptoWrapper
from sgx_crypto_wrapper            import SGXCryptoWrapperSGXError
from sgx_crypto_wrapper            import SGX_CMAC_MAC_SIZE
from sgx_crypto_wrapper            import SGX_SHA256_HASH_SIZE
from sgx_crypto_wrapper            import SGX_AESGCM_MAC_SIZE
from libressl                      import LibreSSLWrapper
from libressl                      import ECC_CURVES, AES_KEY_SIZES
from IntelAttestationServerManager import IntelAttestationServerManager
from IntelAttestationServerManager import IntelAttestationServerError


KEY_STORE_FILE_PATH      = "key_store.bin"

OPENSSM_PORT              = 4500
SIZE_OF_UINT16_T            = 2
SIZE_OF_UINT32_T            = 4
SIZE_OF_UINT64_T            = 8
SIZE_OF_TOTAL_LEN           = SIZE_OF_UINT16_T #uint16_t
SIZE_OF_MSG_HEADER          = SIZE_OF_UINT16_T #uint16_t
SIZE_OF_VERSION_STRING      = 16
SIZE_OF_EC256_PUBLIC_KEY = 64
SIZE_OF_EC256_SIGNATURE  = 64

SIZE_OF_GROUP_ID                  = SIZE_OF_UINT32_T
SIZE_OF_REMOTE_ATTESTATION_MSG_1 = SIZE_OF_EC256_PUBLIC_KEY + SIZE_OF_GROUP_ID
SIZE_OF_REMOTE_ATTESTATION_MSG_3 = 1452
SIZE_OF_SGX_PS_SEC_PROP_DESC      = 256
SIZE_OF_QUOTE_BASENAME              = 32
SIZE_OF_QUOTE_REPORTBODY          = 384

SIZE_OF_SESSION_KEY_NONCE          = 16 
SIZE_OF_ESTABLISH_SESSION_MSG    = SIZE_OF_UINT16_T + SIZE_OF_SESSION_KEY_NONCE
SIZE_OF_AES_128_KEY_IN_BITS      = 128
SIZE_OF_AES_GCM_IV                   = 12
SIZE_OF_AES_GCM_MAC              = 16
SIZE_OF_PROTECTION_SECRET          = 16



SERVICE_PROVIDER_ID_GIVEN_BY_INTEL  = b'\xE8\xCE\x23\xD8\x18\x17\xEA\x81\x78\x42\x90\x68\x7B\x2B\xED\xB7'
DEFAULT_KEY_DERIVATION_ID             = 1

SERVICE_PROVIDER_PRIVATE_KEY         = \
      [ 0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce, 
        0x3b, 0x66, 0xde, 0x11, 0x43, 0x9c, 0x87, 0xec,
        0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6, 0xae, 0xea,
        0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01 ]

SERVICE_PROVIDER_PUBLIC_KEY = \
        [
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38,
    
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06,
        ]

OPENSSM_SECURE_MSG_BAD_HANDLE           = 0x010A
OPENSSM_SECURE_MSG_MAC_MISMATCH         = 0x010D
OPENSSM_SECURE_MSG_SHARED_CUSTUDY_ERROR = 0x010F

class MsgType:
    REQUEST_GET_VERSION           = 1
    RESPONSE_GET_VERSION          = 2
    REQUEST_INIT_START            = 3
    RESPONSE_INIT_MSG1            = 4
    REQUEST_INIT_MSG2             = 5
    RESPONSE_INIT_MSG3            = 6
    REQUEST_ESTABLISH_SESSION      = 7
    RESPONSE_ESTABLISH_SESSION     = 8
    REQUEST_ENCRYPTED_MSG          = 9
    RESPONSE_ENCRYPTED_MSG         = 10

    REQUEST_RESET                 = 0x100
    RESPONSE_RESET                 = 0x101
    REQUEST_SYNC                 = 0x102
    RESPONSE_SYNC                 = 0x103

def OPENSSM_MK_SERVICE_REQUEST( requestID ):
    return 0x7FFF & requestID 

def OPENSSM_MK_SERVICE_RESPONSE( requestID ):
    return 0x8000 | requestID 

def PrintBuff( buff, title ):
    print( "----python----------------%s:" % title )
    for i, byte in enumerate( buff ):
        sys.stdout.write( "0x%2X, " % byte )
        if ( i + 1 ) % 8 == 0:
            print( "" )    

    print( "" )

class SecureMsgType:
    PING                             = OPENSSM_MK_SERVICE_REQUEST ( 0x0000 )
    PING_RESPONSE                    = OPENSSM_MK_SERVICE_RESPONSE( 0x0000 )
    RSA_GENERATE_KEY_PAIR_REQUEST    = OPENSSM_MK_SERVICE_REQUEST ( 0x0001 )
    RSA_GENERATE_KEY_PAIR_RESPONSE   = OPENSSM_MK_SERVICE_RESPONSE( 0x0001 )
    RSA_SIGN_REQUEST                 = OPENSSM_MK_SERVICE_REQUEST ( 0x0002 )
    RSA_SIGN_RESPONSE                = OPENSSM_MK_SERVICE_RESPONSE( 0x0002 )

    ECDSA_GENERATE_KEY_PAIR_REQUEST  = OPENSSM_MK_SERVICE_REQUEST ( 0x0003 )
    ECDSA_GENERATE_KEY_PAIR_RESPONSE = OPENSSM_MK_SERVICE_RESPONSE( 0x0003 )
    ECDSA_SIGN_REQUEST               = OPENSSM_MK_SERVICE_REQUEST ( 0x0004 )
    ECDSA_SIGN_RESPONSE              = OPENSSM_MK_SERVICE_RESPONSE( 0x0004 )

    AES_GCM_GENERATE_KEY_REQUEST     = OPENSSM_MK_SERVICE_REQUEST ( 0x0005 )
    AES_GCM_GENERATE_KEY_RESPONSE    = OPENSSM_MK_SERVICE_RESPONSE( 0x0005 )
    AES_GCM_ENCRYPT_REQUEST          = OPENSSM_MK_SERVICE_REQUEST ( 0x0006 )
    AES_GCM_ENCRYPT_RESPONSE         = OPENSSM_MK_SERVICE_RESPONSE( 0x0006 )
    AES_GCM_DECRYPT_REQUEST          = OPENSSM_MK_SERVICE_REQUEST ( 0x0007 )
    AES_GCM_DECRYPT_RESPONSE         = OPENSSM_MK_SERVICE_RESPONSE( 0x0007 )

    ALLOW_USER_REGISTRATION_REQUEST  = OPENSSM_MK_SERVICE_REQUEST ( 0x0008 )
    ALLOW_USER_REGISTRATION_RESPONSE = OPENSSM_MK_SERVICE_RESPONSE( 0x0008 )
    PROVE_SSM_IDENTITY_REQUEST       = OPENSSM_MK_SERVICE_REQUEST ( 0x0009 )
    PROVE_SSM_IDENTITY_RESPONSE      = OPENSSM_MK_SERVICE_RESPONSE( 0x0009 )

    ARM_KEY_REQUEST                  = OPENSSM_MK_SERVICE_REQUEST ( 0x000A )
    ARM_KEY_RESPONSE                 = OPENSSM_MK_SERVICE_RESPONSE( 0x000A )
    GET_CHALLENGE_REQUEST            = OPENSSM_MK_SERVICE_REQUEST ( 0x000B )
    GET_CHALLENGE_RESPONSE           = OPENSSM_MK_SERVICE_RESPONSE( 0x000B )
    IMPORT_RSA_KEY_REQUEST           = OPENSSM_MK_SERVICE_REQUEST ( 0x000C )
    IMPORT_RSA_KEY_RESPONSE          = OPENSSM_MK_SERVICE_RESPONSE( 0x000C )

    AES_CMAC_REQUEST                 = OPENSSM_MK_SERVICE_REQUEST ( 0x000D )
    AES_CMAC_RESPONSE                = OPENSSM_MK_SERVICE_RESPONSE( 0x000D )

    CREATE_ACCOUNT_REQUEST           = OPENSSM_MK_SERVICE_REQUEST ( 0x000E )
    CREATE_ACCOUNT_RESPONSE          = OPENSSM_MK_SERVICE_RESPONSE( 0x000E )
    TRANSACTION_REQUEST              = OPENSSM_MK_SERVICE_REQUEST ( 0x000F )
    TRANSACTION_RESPONSE             = OPENSSM_MK_SERVICE_RESPONSE( 0x000F )

    GET_CONFIG_ID_REQUEST            = OPENSSM_MK_SERVICE_REQUEST ( 0x0010 )
    GET_CONFIG_ID_RESPONSE           = OPENSSM_MK_SERVICE_RESPONSE( 0x0010 )

    ECDSA_GENERATE_KEY_PAIR_OPENSSL_REQUEST  = OPENSSM_MK_SERVICE_REQUEST  ( 0x0011 )
    ECDSA_GENERATE_KEY_PAIR_OPENSSL_RESPONSE = OPENSSM_MK_SERVICE_RESPONSE ( 0x0011 )
    ECDSA_SIGN_OPENSSL_REQUEST               = OPENSSM_MK_SERVICE_REQUEST  ( 0x0012 )
    ECDSA_SIGN_OPENSSL_RESPONSE              = OPENSSM_MK_SERVICE_RESPONSE ( 0x0012 )

    NUM_SERVICES                     = 0x0013

    ERROR_MSG                             = 0xF000

ALLOW_ALL_SERVICES = [ True ] * SecureMsgType.NUM_SERVICES
    
class SessionEncryptionScheme:
    NULL_ENCRYPTION             = 0
    AES_GCM_128                 = 1

class SessionKeyScheme:
    NULL_ENCRYPTION          = 0
    AES_GCM_128_DOUBLE_NONCE = 1

class QuoteType:
    UNLONKABLE = 0
    LINKABLE   = 1

class RemoteSSMManagerError( Exception ):
    def __init__( self, msg ):
        Exception.__init__( self, msg )
        self.errCode = 0

class RemoteSSMManager:
    def __init__(     self, \
                    sgxCryptoSharedObjectPath = '../tlibcrypto_wrapper/crypto_wrapper.so', \
                    libreSSLSharedObjectPath  = '../libressl_wrapper/libressl_wrapper.so' ):
        self.SetupLogger()
        self.cryptoWrapper         = SGXCryptoWrapper( sgxCryptoSharedObjectPath )
        self.libreSSL                = LibreSSLWrapper( libreSSLSharedObjectPath )
        # self.libreSSL             = LibreSSLWrapper( '/home/ofir/sgx/libressl-2.4.4_orig/libressl-2.4.4/crypto/.libs/libcrypto.so' )
        # self.libreSSL             = LibreSSLWrapper( '/usr/local/lib/libcrypto.so' )
        
        self.IASManager            = IntelAttestationServerManager()
        self.lastTokenID           = 0
        self.pretectionSecrets     = {}

        # self.misreadCounter = 0

    def SetupLogger( self ):
        self.log = logging.getLogger( 'RemoteSSMManager' )
        self.log.setLevel(logging.DEBUG)

        formatter        = logging.Formatter('%(asctime)s %(name)-20s %(levelname)-10s %(message)s')
        consoleHandler = logging.StreamHandler()
        consoleHandler.setLevel(logging.DEBUG)
        consoleHandler.setFormatter(formatter)
        
        self.log.handlers = []
        self.log.addHandler(consoleHandler)        

    def ConnectToSSM( self, ipAddress ):
        self.log.info( "Connecting to %s" % ipAddress )

        self.IsConnected  = False
        self.ssmSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ssmSocket.connect( ( ipAddress, OPENSSM_PORT ))
        self.IsConnected  = True

        fcntl.fcntl(self.ssmSocket, fcntl.F_SETFL, os.O_NONBLOCK)

        self.log.info( "Connected!" )
        self.leftoversOnSocket = ''

    def DisconnectFromSSM( self ):
        self.log.info( "DisconnectFromSSM" )
        try:
            if self.IsConnected is True:
                self.SendResetRequest()
        except:
            pass

        self.ssmSocket.close()
        self.IsConnected = False

    def SendResetRequest( self ):
        self.log.debug( "SendResetRequest" )
        if self.IsConnected is False:
            raise Exception( "Not connected to SSM" )

        msgSize = SIZE_OF_TOTAL_LEN + SIZE_OF_MSG_HEADER
        msg      = b''
        msg     += struct.pack( "H", msgSize)
        msg     += struct.pack( "H", MsgType.REQUEST_RESET )

        self.ssmSocket.send( msg )
        msgRaw = self.ReadMsgFromSocket()
        pprint.pprint( msgRaw )
        msgType = self.GetMsgType( msgRaw )
        self.VerifyEqual(     msgType, 
                            MsgType.RESPONSE_RESET, 
                            errMsg="value = %d, instead of expected %d" % ( msgType, MsgType.RESPONSE_RESET ))
        print( "########### Got reset response ")

    def GetMsgType( self, msgRaw ):
        curretPosition  = SIZE_OF_UINT16_T;
        msgtype           = struct.unpack( "H", msgRaw[ curretPosition:curretPosition + SIZE_OF_UINT16_T ] )[0]
        
        return msgtype

    def GetVersion( self ):
        self.log.debug( "GetVersion" )

        self.SendVersionRequest()

        #get reply:
        msgRaw = self.ReadMsgFromSocket()
        
        curretPosition  = 0;
        msgLength        = struct.unpack( "H", msgRaw[ curretPosition:curretPosition + SIZE_OF_UINT16_T ] )[0]
        curretPosition += SIZE_OF_UINT16_T;
        expectedLength  = SIZE_OF_TOTAL_LEN + SIZE_OF_MSG_HEADER + 2*SIZE_OF_VERSION_STRING
        self.VerifyEqual( msgLength, expectedLength, errMsg="totalLength = %d, instead of expected %d" % ( msgLength, expectedLength ))

        msgtype           = struct.unpack( "H", msgRaw[ curretPosition:curretPosition + SIZE_OF_UINT16_T ] )[0]
        curretPosition += SIZE_OF_UINT16_T;        
        self.VerifyEqual( msgtype, MsgType.RESPONSE_GET_VERSION, errMsg="value = %d, instead of expected %d" % ( msgtype, MsgType.RESPONSE_GET_VERSION ))

        serverVersionString = msgRaw[ curretPosition: curretPosition + SIZE_OF_VERSION_STRING ]
        curretPosition += SIZE_OF_VERSION_STRING
        
        enclaveVersionString = msgRaw[ curretPosition: curretPosition + SIZE_OF_VERSION_STRING ]
        curretPosition += SIZE_OF_VERSION_STRING        
        
        return serverVersionString, enclaveVersionString

    def VerifyEqual( self, op1, op2, errMsg ):
        if( op1 != op2 ):
            self.log.error( errMsg )
            raise Exception( errMsg )

    def SendVersionRequest( self ):
        if self.IsConnected is False:
            raise Exception( "Not connected to SSM" )

        msgSize = SIZE_OF_TOTAL_LEN + SIZE_OF_MSG_HEADER
        msg      = b''
        msg     += struct.pack( "H", msgSize)
        msg     += struct.pack( "H", MsgType.REQUEST_GET_VERSION )
        
        self.ssmSocket.send( msg )

    def RemoteAttestation_GetMsg1( self ):
        self.log.debug( "RemoteAttestation_getMsg1" )

        self.SendInitSSMRequest()    
        
        #get reply:
        msgRaw = self.ReadMsgFromSocket()

        curretPosition  = 0;
        msgLength        = struct.unpack( "H", msgRaw[ curretPosition:curretPosition + SIZE_OF_UINT16_T ] )[0]
        curretPosition += SIZE_OF_UINT16_T;
        expectedLength  = SIZE_OF_TOTAL_LEN + SIZE_OF_MSG_HEADER + SIZE_OF_REMOTE_ATTESTATION_MSG_1
        self.VerifyEqual( msgLength, expectedLength, errMsg="totalLength = %d, instead of expected %d" % ( msgLength, expectedLength ))

        msgtype           = struct.unpack( "H", msgRaw[ curretPosition:curretPosition + SIZE_OF_UINT16_T ] )[0]
        curretPosition += SIZE_OF_UINT16_T;        
        expectedMsgType = MsgType.RESPONSE_INIT_MSG1
        self.VerifyEqual( msgtype, expectedMsgType, errMsg="value = %d, instead of expected %d" % ( msgtype, expectedMsgType ))

        enclavePublicKey = msgRaw[ curretPosition: curretPosition + SIZE_OF_EC256_PUBLIC_KEY ]
        curretPosition  += SIZE_OF_EC256_PUBLIC_KEY
        
        groupID = struct.unpack( "I", msgRaw[ curretPosition: curretPosition + SIZE_OF_GROUP_ID ] )[0]
        curretPosition += SIZE_OF_GROUP_ID        

        msg1 = {}
        msg1[ 'group-ID' ]                    = groupID
        msg1[ 'enclave-public-key' ]      = enclavePublicKey
        return msg1

    def SendInitSSMRequest( self ):
        self.log.debug( "SendInitSSMRequest" )
        if self.IsConnected is False:
            raise Exception( "Not connected to SSM" )

        msgSize = SIZE_OF_TOTAL_LEN + SIZE_OF_MSG_HEADER
        msg      = b''
        msg     += struct.pack( "H", msgSize)
        msg     += struct.pack( "H", MsgType.REQUEST_INIT_START )

        self.ssmSocket.send( msg )

    def GenerateKeyPair( self ):
        self.privateKey, self.publicKey = self.cryptoWrapper.CreateECC256_keyPair()

    def ComputeSharedSecret( self ):
        self.sharedSecret = self.cryptoWrapper.ComputeSharedSecret( self.privateKey, self.enclavePublicKey )

    def ComputeSharedDerivedSecrets( self ):
        self.key_SMK = self.cryptoWrapper.DeriveKey( self.sharedSecret, b"SMK\x00" )
        self.key_SK  = self.cryptoWrapper.DeriveKey( self.sharedSecret, b"SK\x00" )
        self.key_VK  = self.cryptoWrapper.DeriveKey( self.sharedSecret, b"VK\x00" )
        self.key_MK  = self.cryptoWrapper.DeriveKey( self.sharedSecret, b"MK\x00" )

        # print( "--------------------key_MK key:" )
        # for i, byte in enumerate( self.key_MK ):
        #     sys.stdout.write( "0x%2X, " % byte )
        #     if ( i + 1 ) % 8 == 0:
        #         print( "" )    

        # print( "--------------------key_SK key:" )
        # for i, byte in enumerate( self.key_SK ):
        #     sys.stdout.write( "0x%2X, " % byte )
        #     if ( i + 1 ) % 8 == 0:
        #         print( "" )    

    def SignPublicKeys( self, enclavePublicKey ):
        # g_b Service provider public key
        # g_a Enclave public key
        gb_ga = b""
        gb_ga += bytearray( self.publicKey )
        gb_ga += bytearray( enclavePublicKey )


        signatureOf_gb_ga = self.cryptoWrapper.SignECDSA(     bytearray( gb_ga ), 
                                                            bytearray( SERVICE_PROVIDER_PRIVATE_KEY ) )
        # if( False == self.cryptoWrapper.VerifyECDSASignature(     gb_ga, 
        #                                                         signatureOf_gb_ga, 
        #                                                         SERVICE_PROVIDER_PUBLIC_KEY ) ):
        #     raise Exception( "Error while signing gb_ga" )
        # self.log.debug( "$"*40 +  "Signature OK" )

        # print( "$"*40 +  "SERVICE_PROVIDER_PUBLIC_KEY:" )
        # for i, byte in enumerate( SERVICE_PROVIDER_PUBLIC_KEY ):
        #     sys.stdout.write( "0x%2X, " % byte )
        #     if ( i + 1 ) % 8 == 0:
        #         print( "" )

        # print( "$"*40 +  "gb_ga:" )
        # for i, byte in enumerate( gb_ga ):
        #     sys.stdout.write( "0x%2X, " % byte )
        #     if ( i + 1 ) % 8 == 0:
        #         print( "" )

        # print( "$"*40 +  "signature of gb_ga:" )
        # for i, byte in enumerate( signatureOf_gb_ga ):
        #     sys.stdout.write( "0x%2X, " % byte )
        #     if ( i + 1 ) % 8 == 0:
        #         print( "" )


        return signatureOf_gb_ga

    def ComputeMsg2MAC( self, msg2 ):
        #mac_smk(g_b||spid||quote_type||kdf_id||sign_gb_ga)
        dataToMAC = bytearray( self.publicKey )
        dataToMAC += bytearray( SERVICE_PROVIDER_ID_GIVEN_BY_INTEL )

        quoteTypeSerilized = struct.pack( "H", msg2[ 'Quote-Type' ] )
        dataToMAC += quoteTypeSerilized

        keyDerivationIDSerilizaed = struct.pack( "H", msg2[ 'Key-derivation-id' ] )
        dataToMAC += keyDerivationIDSerilizaed    

        dataToMAC += bytearray( msg2[ 'signed-public-keys' ] )    

        mac = self.cryptoWrapper.Rijndael128_CMAC( dataToMAC, self.key_SMK )            

        return dataToMAC, mac


    def GenerateAttestationMsg2( self, enclavePublicKey, groupID ):
        msg2 = {}
        msg2[ 'service-provider-public-key'     ] = self.publicKey
        msg2[ 'SPID'                               ] = SERVICE_PROVIDER_ID_GIVEN_BY_INTEL
        msg2[ 'Quote-Type'                         ] = QuoteType.LINKABLE
        msg2[ 'Key-derivation-id'                 ] = DEFAULT_KEY_DERIVATION_ID
        msg2[ 'signed-public-keys'              ] = self.SignPublicKeys( enclavePublicKey )

        macedData, mac = self.ComputeMsg2MAC( msg2 ) #mac_smk(g_b||spid||quote_type||kdf_id||sign_gb_ga)
        msg2[ 'MAC'                             ] = mac

        sigRL = self.IASManager.GetSignatureRevocationList( groupID )
        msg2[ 'sigRL-size'                         ] = len( sigRL )
        msg2[ 'sigRL'                             ] = sigRL

        sigRLSize_serilized = struct.pack( "I", msg2[ 'sigRL-size' ] )
        msg2Serilized         = macedData + mac + sigRLSize_serilized + sigRL

        return msg2, msg2Serilized

    def RemoteAttestation_ProcessMsg1( self, msg1 ):
        self.enclavePublicKey = msg1[ 'enclave-public-key' ]
        self.ComputeSharedSecret             ()
        self.ComputeSharedDerivedSecrets     ()
        msg2, msg2Bytes = self.GenerateAttestationMsg2( msg1[ 'enclave-public-key' ], msg1[ 'group-ID' ]  )

        msgSize = SIZE_OF_TOTAL_LEN + SIZE_OF_MSG_HEADER + len( msg2Bytes )
        msg      = b''
        msg     += struct.pack( "H", msgSize)
        msg     += struct.pack( "H", MsgType.REQUEST_INIT_MSG2 )
        msg     += msg2Bytes

        self.ssmSocket.send( msg )

    def VerifyBuffersEqual( self, buff1, buff2 ):
        if len( buff1 ) != len( buff2 ):
            raise RemoteSSMManagerError( "Buffers have different sizes: %d != %d" % ( len( buff1 ), len( buff2 ) ) )

        for i in range( len( buff1 ) ):
            if buff1[ i ] != buff2[ i ]:
                raise RemoteSSMManagerError( "Buffers are different in byte %d", i  )                


    def ParseQuoteReport( self, rawQuoteReport ):
        SGX_CPUSVN_SIZE   = 16
        RESERVED1_SIZE    = 28
        RESERVED2_SIZE    = 32
        RESERVED3_SIZE    = 96
        RESERVED4_SIZE    = 60
        ATTRIBUTES_SIZE   = 16
        SGX_HASH_SIZE     = 32
        USER_DATA_SIZE    = 64

        # from common/inc/sgx_report.h:
        # typedef struct _report_body_t
        # {
        #     sgx_cpu_svn_t           cpu_svn;        /* (  0) Security Version of the CPU */
        #     sgx_misc_select_t       misc_select;    /* ( 16) Which fields defined in SSA.MISC */
        #     uint8_t                 reserved1[28];  /* ( 20) */
        #     sgx_attributes_t        attributes;     /* ( 48) Any special Capabilities the Enclave possess */
        #     sgx_measurement_t       mr_enclave;     /* ( 64) The value of the enclave's ENCLAVE measurement */
        #     uint8_t                 reserved2[32];  /* ( 96) */
        #     sgx_measurement_t       mr_signer;      /* (128) The value of the enclave's SIGNER measurement */
        #     uint8_t                 reserved3[96];  /* (160) */
        #     sgx_prod_id_t           isv_prod_id;    /* (256) Product ID of the Enclave */
        #     sgx_isv_svn_t           isv_svn;        /* (258) Security Version of the Enclave */
        #     uint8_t                 reserved4[60];  /* (260) */
        #     sgx_report_data_t       report_data;    /* (320) Data provided by the user */
        # } sgx_report_body_t;

        

        report = {}
        curretPosition = 0

        report[ 'CPU-SVN'    ]     =  rawQuoteReport[ curretPosition: curretPosition + SGX_CPUSVN_SIZE ]
        curretPosition            += SGX_CPUSVN_SIZE

        report[ 'CPU-SVN'    ]     =  struct.unpack( "I", rawQuoteReport[ curretPosition : curretPosition + SIZE_OF_UINT32_T ] )[0]
        curretPosition            += SIZE_OF_UINT32_T 

        curretPosition += RESERVED1_SIZE

        report[ 'Attributes' ]  = rawQuoteReport[ curretPosition : curretPosition + ATTRIBUTES_SIZE ]
        curretPosition            += ATTRIBUTES_SIZE

        report[ 'MRENCLAVE'  ]  = rawQuoteReport[ curretPosition : curretPosition + SGX_HASH_SIZE ]
        curretPosition            += SGX_HASH_SIZE

        curretPosition += RESERVED2_SIZE

        report[ 'MRSIGNER'   ]  = rawQuoteReport[ curretPosition : curretPosition + SGX_HASH_SIZE ]
        curretPosition            += SGX_HASH_SIZE

        curretPosition += RESERVED3_SIZE

        report[ 'Vendor-product-ID'  ] =  struct.unpack( "H", rawQuoteReport[ curretPosition : curretPosition + SIZE_OF_UINT16_T ] )[0]
        curretPosition                      += SIZE_OF_UINT16_T 

        report[ 'Vendor-product-SVN' ] =  struct.unpack( "H", rawQuoteReport[ curretPosition : curretPosition + SIZE_OF_UINT16_T ] )[0]
        curretPosition                      += SIZE_OF_UINT16_T 

        curretPosition += RESERVED4_SIZE

        report[ 'Report-data'          ] = rawQuoteReport[ curretPosition : curretPosition + USER_DATA_SIZE ]
        curretPosition                      += USER_DATA_SIZE 

        if( curretPosition != SIZE_OF_QUOTE_REPORTBODY ):
            raise RemoteSSMManagerError( "Error parsing quote report body. curretPosition = %d" % curretPosition )

        return report

    def VerifyAllZeros( self, buff ):
        for i in range( len( buff ) ):
            if buff[ i ] != 0:
                raise RemoteSSMManagerError( "Should be all zeros. Byte %d is non zero." % i)

    def ParseQuote( self, rawQuote ):
        # from common/inc/sgx_quote.h:
        # typedef struct _quote_t
        # {
        #     uint16_t            version;        /* 0   */
        #     uint16_t            sign_type;      /* 2   */
        #     sgx_epid_group_id_t epid_group_id;  /* 4   */
        #     sgx_isv_svn_t       qe_svn;         /* 8   */
        #     sgx_isv_svn_t       pce_svn;        /* 10  */
        #     uint32_t            xeid;           /* 12  */
        #     sgx_basename_t      basename;       /* 16  */
        #     sgx_report_body_t   report_body;    /* 48  */
        #     uint32_t            signature_len;  /* 432 */
        #     uint8_t             signature[];    /* 436 */
        # } sgx_quote_t;

        quote             = {}
        curretPosition     = 0

        quote[ 'QuoteVersion' ]      = struct.unpack( "H", rawQuote[ curretPosition:curretPosition + SIZE_OF_UINT16_T ] )[0]
        curretPosition                  += SIZE_OF_UINT16_T  

        quote[ 'QuoteSignType' ]     = struct.unpack( "H", rawQuote[ curretPosition:curretPosition + SIZE_OF_UINT16_T ] )[0]
        curretPosition                  += SIZE_OF_UINT16_T  

        quote[ 'QuoteGroupID' ]         = struct.unpack( "I", rawQuote[ curretPosition:curretPosition + SIZE_OF_UINT32_T ] )[0]
        curretPosition                  += SIZE_OF_UINT32_T  

        quote[ 'QuoteEnclaveSVN' ]     = struct.unpack( "H", rawQuote[ curretPosition:curretPosition + SIZE_OF_UINT16_T ] )[0]
        curretPosition                  += SIZE_OF_UINT16_T  

        quote[ 'QuotePCESVN' ]         = struct.unpack( "H", rawQuote[ curretPosition:curretPosition + SIZE_OF_UINT16_T ] )[0]
        curretPosition                  += SIZE_OF_UINT16_T  

        quote[ 'QuoteXEID' ]         = struct.unpack( "I", rawQuote[ curretPosition:curretPosition + SIZE_OF_UINT32_T ] )[0]
        curretPosition                  += SIZE_OF_UINT32_T 

        quote[ 'QuoteBaseName' ]     = rawQuote[ curretPosition : curretPosition +  SIZE_OF_QUOTE_BASENAME ]
        curretPosition                  += SIZE_OF_QUOTE_BASENAME 

        quote[ 'QuoteReportBody' ]     = self.ParseQuoteReport( rawQuote[ curretPosition : curretPosition + SIZE_OF_QUOTE_REPORTBODY ] )
        curretPosition                  += SIZE_OF_QUOTE_REPORTBODY 

        quote[ 'QuoteSignatureSize' ]= struct.unpack( "I", rawQuote[ curretPosition : curretPosition + SIZE_OF_UINT32_T ] )[0]
        curretPosition                  += SIZE_OF_UINT32_T 

        quote[ 'QuoteSignature' ]   = rawQuote[ curretPosition : curretPosition + quote[ 'QuoteSignatureSize' ]]
        curretPosition                  += quote[ 'QuoteSignatureSize' ] 

        return quote

    def RemoteAttestation_GetMsg3( self ):
        self.log.debug( "RemoteAttestation_GetMsg3" )
        msgRaw = self.ReadMsgFromSocket()

        msg3   = {}

        curretPosition  = 0;
        msgLength        = struct.unpack( "H", msgRaw[ curretPosition:curretPosition + SIZE_OF_UINT16_T ] )[0]
        curretPosition += SIZE_OF_UINT16_T;
        expectedLength  = SIZE_OF_TOTAL_LEN + SIZE_OF_MSG_HEADER + SIZE_OF_REMOTE_ATTESTATION_MSG_3
        self.VerifyEqual( msgLength, expectedLength, errMsg="totalLength = %d, instead of expected %d" % ( msgLength, expectedLength ))

        msgtype           = struct.unpack( "H", msgRaw[ curretPosition:curretPosition + SIZE_OF_UINT16_T ] )[0]
        curretPosition += SIZE_OF_UINT16_T;        
        expectedMsgType = MsgType.RESPONSE_INIT_MSG3
        self.VerifyEqual( msgtype, expectedMsgType, errMsg="value = %d, instead of expected %d" % ( msgtype, expectedMsgType ))

        # from common/inc/sgx_key_exchange.h:
        # typedef struct _ra_msg3_t
        # {
        #     sgx_mac_t                mac;         /* mac_smk(g_a||ps_sec_prop||quote) */
        #     sgx_ec256_public_t       g_a;         /* the Endian-ness of Ga is Little-Endian */
        #     sgx_ps_sec_prop_desc_t   ps_sec_prop;
        #     uint8_t                  quote[];
        # } sgx_ra_msg3_t;

        msg3[ 'MAC' ]    = msgRaw[ curretPosition : curretPosition + SGX_CMAC_MAC_SIZE ]
        curretPosition += SGX_CMAC_MAC_SIZE
            
        # We already have enclavePublicKey from msg1, this can be ignored
        enclavePublicKey = msgRaw[ curretPosition: curretPosition + SIZE_OF_EC256_PUBLIC_KEY ] 
        curretPosition  += SIZE_OF_EC256_PUBLIC_KEY 
        self.VerifyBuffersEqual( enclavePublicKey, self.enclavePublicKey ) 

        # SDK documentation states this is all zeros
        platformServicesProperties     = msgRaw[ curretPosition: curretPosition + SIZE_OF_SGX_PS_SEC_PROP_DESC ] 
        curretPosition             += SIZE_OF_SGX_PS_SEC_PROP_DESC  
        self.VerifyAllZeros( platformServicesProperties )
        
        #Parse quote
        msg3[ 'Quote-Raw' ] = msgRaw[ curretPosition : ]
        msg3[ 'Quote'     ] = self.ParseQuote( msg3[ 'Quote-Raw' ] )

        # pprint.pprint( msg3 )

        return msg3

    def VerifyAttestationMsg3MAC( self, msg3 ):
        #mac_smk(g_a||ps_sec_prop||quote)
        
        dataToMAC = b""
        dataToMAC += bytearray( self.enclavePublicKey )
        dataToMAC += bytearray( b"\x00" * SIZE_OF_SGX_PS_SEC_PROP_DESC ) #SDK documentation says it should always be zeros
        dataToMAC += bytearray( msg3[ 'Quote-Raw' ] )

        mac = self.cryptoWrapper.Rijndael128_CMAC( dataToMAC, self.key_SMK )

        if len( mac ) != SGX_CMAC_MAC_SIZE:
            raise RemoteSSMManagerError( "Error computing MAC on Msg3" )

        MAC_VALID = True
        for i in range( len( mac ) ):
            MAC_VALID &= ( mac[ i ] == msg3[ 'MAC' ][ i ] )

        if not MAC_VALID:
            raise RemoteSSMManagerError( "Invalid MAC in Msg3" )

    def VerifyAttestationReportSHA256( self, msg3 ):
        # H = SHA256(ga || gb || VK_CMAC)
        shaedData = b""
        shaedData += self.enclavePublicKey
        shaedData += self.publicKey
        shaedData += self.key_VK

        digest = self.cryptoWrapper.SHA256( shaedData )

        isDigestValid = True
        expectedDigest = msg3[ 'Quote' ][ 'QuoteReportBody' ][ 'Report-data' ][ 0 : SGX_SHA256_HASH_SIZE ]

        for i in range( len( expectedDigest ) ):
            isDigestValid &= ( digest[ i ] == expectedDigest[ i ] )

        if not isDigestValid:
            raise RemoteSSMManagerError( "Invalid Quote report in Msg3" )

    def VerifyQuoteWithIntelAttestationServer( self, msg3 ):
        self.IASManager.VerifyQuote( msg3[ 'Quote-Raw' ] )

    def RemoteAttestation_ProcessMsg3( self, msg3 ):
        self.VerifyAttestationMsg3MAC             ( msg3 )
        self.VerifyAttestationReportSHA256        ( msg3 )
        self.VerifyQuoteWithIntelAttestationServer( msg3 )

    def InitSSM( self, performRemoteAttestation = True ):
        self.GenerateKeyPair                   ()

        if performRemoteAttestation:
            self.PerformRemoteAttestationHandshake()

    def PerformRemoteAttestationHandshake( self ):
        msg1 = self.RemoteAttestation_GetMsg1()
        self.RemoteAttestation_ProcessMsg1( msg1 )

        msg3 = self.RemoteAttestation_GetMsg3()
        self.RemoteAttestation_ProcessMsg3( msg3 )

    def CalcUserID( self ):
        return self.cryptoWrapper.SHA256( self.publicKey )

    def SendEstablishSessionRequest( self, localNonce ):
        # typedef struct __attribute__((__packed__)) 
        # {
        #     UserID                 userID;
        #     SessionKeysScheme     scheme;
        #     uint8_t                 extraData[];
        # } EstablishSessionKeysMsg;

        msg      = struct.pack( "H", MsgType.REQUEST_ESTABLISH_SESSION )
        msg     += self.CalcUserID()
        msg     += struct.pack( "H", SessionKeyScheme.AES_GCM_128_DOUBLE_NONCE )
        msg     += localNonce

        msgSize = len( msg ) + SIZE_OF_TOTAL_LEN
        msg     = struct.pack( "H", msgSize) + msg

        self.ssmSocket.send( msg )

    def SendEstablishInsecureSessionRequest( self ):
        # typedef struct __attribute__((__packed__)) 
        # {
        #     UserID                 userID;
        #     SessionKeysScheme     scheme;
        #     uint8_t                 extraData[];
        # } EstablishSessionKeysMsg;

        msg      = struct.pack( "H", MsgType.REQUEST_ESTABLISH_SESSION )
        msg     += self.CalcUserID()
        msg     += struct.pack( "H", SessionKeyScheme.NULL_ENCRYPTION )

        msgSize = len( msg ) + SIZE_OF_TOTAL_LEN
        msg     = struct.pack( "H", msgSize) + msg

        self.ssmSocket.send( msg )

    def EstablishSessionKeys( self ):
        self.log.debug( "EstablishSessionKeys" )
        if self.IsConnected is False:
            raise Exception( "Not connected to SSM" )

        localNonce = os.urandom( SIZE_OF_SESSION_KEY_NONCE )
        self.SendEstablishSessionRequest( localNonce )

        #get reply:
        msgRaw = self.ReadMsgFromSocket()        
        # typedef struct __attribute__((__packed__)) 
        # {
        #     uint8_t                     data[];
        # } EstablishSessionKeysResponse;

        curretPosition  = 0;
        msgLength        = struct.unpack( "H", msgRaw[ curretPosition:curretPosition + SIZE_OF_UINT16_T ] )[0]
        curretPosition += SIZE_OF_UINT16_T;
        expectedLength  = SIZE_OF_TOTAL_LEN + SIZE_OF_ESTABLISH_SESSION_MSG
        self.VerifyEqual( msgLength, expectedLength, errMsg="totalLength = %d, instead of expected %d" % ( msgLength, expectedLength ))

        msgtype           = struct.unpack( "H", msgRaw[ curretPosition:curretPosition + SIZE_OF_UINT16_T ] )[0]
        curretPosition += SIZE_OF_UINT16_T;        
        self.VerifyEqual( msgtype, MsgType.RESPONSE_ESTABLISH_SESSION, errMsg="value = %d, instead of expected %d" % ( msgtype, MsgType.RESPONSE_ESTABLISH_SESSION ))

        ssmNonce = msgRaw[ curretPosition: curretPosition + SIZE_OF_SESSION_KEY_NONCE ]
        curretPosition += SIZE_OF_SESSION_KEY_NONCE
        
        combinedNonce = localNonce + ssmNonce

        # Key derivation data,  as officially defined in NIST SP 800-108, and in "include/types.hpp"
        # struct {
        #     uint8_t     counter;
        #     uint16_t    label;
        #     uint8_t     alwaysZero;
        #     uint8_t     context[ KEY_DERIVATION_CONTEXT_SIZE ];
        #     uint16_t    lengthOfDerivedKey;
        # };
        keyDerivationBuffer  = b"\x01"                                             #counter
        keyDerivationBuffer += b"EK"                                              #label
        keyDerivationBuffer += b"\x00"                                             #alwaysZero
        keyDerivationBuffer += combinedNonce                                     #context
        keyDerivationBuffer += struct.pack( "H", SIZE_OF_AES_128_KEY_IN_BITS )  #lengthOfDerivedKey

        self.key_session        = self.cryptoWrapper.Rijndael128_CMAC( keyDerivationBuffer, self.key_SK );
        self.sessionEncryptMsgCounter = 0
        self.sessionDecryptMsgCounter = 0
        self.sessionProtectionScheme  = SessionEncryptionScheme.AES_GCM_128

    def ParseInsecureEstablishSessionResponse( self, msgRaw ):
        curretPosition  = 0;
        msgLength        = struct.unpack( "H", msgRaw[ curretPosition:curretPosition + SIZE_OF_UINT16_T ] )[0]
        curretPosition += SIZE_OF_UINT16_T;
        expectedLength  = SIZE_OF_TOTAL_LEN + SIZE_OF_MSG_HEADER
        self.VerifyEqual( msgLength, expectedLength, errMsg="totalLength = %d, instead of expected %d" % ( msgLength, expectedLength ))

        msgtype           = struct.unpack( "H", msgRaw[ curretPosition:curretPosition + SIZE_OF_UINT16_T ] )[0]
        curretPosition += SIZE_OF_UINT16_T;        
        self.VerifyEqual( msgtype, MsgType.RESPONSE_ESTABLISH_SESSION, errMsg="value = %d, instead of expected %d" % ( msgtype, MsgType.RESPONSE_ESTABLISH_SESSION ))

        self.sessionProtectionScheme  = SessionKeyScheme.NULL_ENCRYPTION
        self.sessionEncryptMsgCounter = 0
        self.sessionDecryptMsgCounter = 0

    def EstablishInsecureSession( self ):
        self.log.debug( "EstablishInsecureSession" )
        if self.IsConnected is False:
            raise Exception( "Not connected to SSM" )

        self.SendEstablishInsecureSessionRequest()

        #get reply:
        msgRaw         = self.ReadMsgFromSocket()
        self.ParseInsecureEstablishSessionResponse( msgRaw)

    def CreateEncryptedMsg( self, msgToEncrypt ):
        # typedef struct __attribute__((__packed__)) 
        # {
        #     uint16_t                    encryptionScheme;  //See SessionEncryptionScheme
        #     uint64_t                     msgNumber;   //The IV is derived from this value. AES-GCM is EXTREMELY SENSITIVE to repeated IVs.
        #                                              //Therefore, this number should be used for debugging purposes only. The counter should be 
        #                                              //independently maintained by both parties, to avoid same-IV attacks
        #     uint32_t                     userID;    
        #     sgx_aes_gcm_128bit_tag_t     mac;    
        #     uint16_t                    cipherSize;
        #     uint8_t                         ciphertext[];
        # } EncryptedMsg;

        DEFAULT_USER_ID         = 0

        self.sessionEncryptMsgCounter += 1

        if self.sessionProtectionScheme == SessionEncryptionScheme.AES_GCM_128:
            IV         = b"\x01\x00\x00\x00" + struct.pack( "Q", self.sessionEncryptMsgCounter)
            NO_AAD     = None
            cipherText, mac = self.cryptoWrapper.Rijndael128GCM_Encrypt(     self.key_session, 
                                                                            bytearray( IV ), 
                                                                            bytearray( msgToEncrypt ), 
                                                                            NO_AAD )

        elif self.sessionProtectionScheme == SessionEncryptionScheme.NULL_ENCRYPTION:
            cipherText = msgToEncrypt
            mac        = b"\x00" * SIZE_OF_AES_GCM_MAC

        else:
            raise Exception( "Unknown sessionProtectionScheme: %d" % self.sessionProtectionScheme )

        msg =  struct.pack( "H", self.sessionProtectionScheme)
        msg += struct.pack( "Q", self.sessionEncryptMsgCounter )
        msg += struct.pack( "I", DEFAULT_USER_ID )
        msg += mac
        msg += struct.pack( "H", len( cipherText ) )
        msg += cipherText

        return msg

    def BuildPingMsg( self, payload ):
        msgToEncrypt = struct.pack( "H", SecureMsgType.PING )
        msgToEncrypt += struct.pack( "I", payload )
        
        return  self.CreateEncryptedMsg( msgToEncrypt )

    def SendPingMsg( self, payload ):
        msg     = struct.pack( "H", MsgType.REQUEST_ENCRYPTED_MSG )
        msg     += self.BuildPingMsg( payload )

        #Attach totalLen as PREFIX:
        msgSize = len( msg ) + SIZE_OF_TOTAL_LEN
        msg     = struct.pack( "H", msgSize) + msg

        self.ssmSocket.send( msg )

        return msgSize

    def ParseEncryptedMsg( self, encryptedMsg ):
        # typedef struct __attribute__((__packed__)) 
        # {
        #     uint16_t                    encryptionScheme;  //See SessionEncryptionScheme
        #     uint64_t                     msgNumber;   //The IV is derived from this value. AES-GCM is EXTREMELY SENSITIVE to repeated IVs.
        #                                              //Therefore, this number should be used for debugging purposes only. The counter should be 
        #                                              //independently maintained by both parties, to avoid same-IV attacks
        #     uint32_t                     userID;    
        #     sgx_aes_gcm_128bit_tag_t     mac;    
        #     uint16_t                    cipherSize;
        #     uint8_t                         ciphertext[];
        # } EncryptedMsg;

        curretPosition      = 0
        encryptionScheme = struct.unpack( "H", encryptedMsg[ curretPosition:curretPosition + SIZE_OF_UINT16_T ] )[0]
        curretPosition  += SIZE_OF_UINT16_T;
        # self.VerifyEqual( encryptionScheme,  SessionEncryptionScheme.AES_GCM_128, errMsg="encryptionScheme = %d, instead of expected %d" % ( encryptionScheme,  SessionEncryptionScheme.AES_GCM_128 ))

        msgNumber         = struct.unpack( "Q", encryptedMsg[ curretPosition:curretPosition + SIZE_OF_UINT64_T ] )[0]
        curretPosition    += SIZE_OF_UINT64_T

        userID           = struct.unpack( "I", encryptedMsg[ curretPosition:curretPosition + SIZE_OF_UINT32_T ] )[0]
        curretPosition    += SIZE_OF_UINT32_T

        mac              = encryptedMsg[ curretPosition : curretPosition + SGX_AESGCM_MAC_SIZE ]
        curretPosition     += SGX_AESGCM_MAC_SIZE

        cipherSize          = struct.unpack( "H", encryptedMsg[ curretPosition:curretPosition + SIZE_OF_UINT16_T ] )[0]
        curretPosition  += SIZE_OF_UINT16_T;
        expectedCipherSize = len( encryptedMsg ) - curretPosition
        self.VerifyEqual( cipherSize, expectedCipherSize, errMsg="cipherSize = %d, instead of expected %d" % ( cipherSize, expectedCipherSize ) )

        cipherText          = encryptedMsg[ curretPosition : ] 


        self.sessionDecryptMsgCounter += 1
        # if self.sessionDecryptMsgCounter != msgNumber:
        #     self.log.warning( "self.sessionDecryptMsgCounter != msgNumber (%d != %d)" % (self.sessionDecryptMsgCounter, msgNumber ) )

        if self.sessionProtectionScheme == SessionEncryptionScheme.AES_GCM_128:
            IV           = b"\x02\x00\x00\x00" + struct.pack( "Q", msgNumber )
            NO_AAD    = None

            secureMsgRaw  = self.cryptoWrapper.Rijndael128GCM_Decrypt(     self.key_session, 
                                                                        bytearray( IV ), 
                                                                        bytearray( cipherText ), 
                                                                        NO_AAD, 
                                                                        bytearray( mac ) )
        
        elif self.sessionProtectionScheme == SessionEncryptionScheme.NULL_ENCRYPTION:
            secureMsgRaw = cipherText

        else:
            raise Exception( "Unknown sessionProtectionScheme: %d" % self.sessionProtectionScheme )

        curretPosition = 0
        secureMsg = {}
        secureMsg[ 'Type' ] = struct.unpack( "H", secureMsgRaw[ curretPosition:curretPosition + SIZE_OF_UINT16_T ] )[0]
        curretPosition      += SIZE_OF_UINT16_T;

        secureMsg[ 'Body' ] = secureMsgRaw[ curretPosition : ] 

        # print( "++++++++++++++++++++++secureMsgRaw: " )
        # for i, byte in enumerate( secureMsgRaw ):
        #     sys.stdout.write( "0x%2X, " % byte )
        #     if ( i + 1 ) % 8 == 0:
        #         print( "" )
        # print( "" )
        # pprint.pprint( secureMsg )

        return secureMsg;
        
    def ParseMsg( self, msgRaw, expectedMsgType = MsgType.RESPONSE_ENCRYPTED_MSG ):
        curretPosition  = 0;
        msgLength        = struct.unpack( "H", msgRaw[ curretPosition:curretPosition + SIZE_OF_UINT16_T ] )[0]
        curretPosition += SIZE_OF_UINT16_T;
        
        msgtype           = struct.unpack( "H", msgRaw[ curretPosition:curretPosition + SIZE_OF_UINT16_T ] )[0]
        curretPosition += SIZE_OF_UINT16_T;        
        self.VerifyEqual( msgtype, expectedMsgType, errMsg="value = %d, instead of expected %d" % ( msgtype, MsgType.RESPONSE_ENCRYPTED_MSG ))

        msg = msgRaw[ curretPosition : ]
        if expectedMsgType == MsgType.RESPONSE_ENCRYPTED_MSG:
            return self.ParseEncryptedMsg( msg )
        #else    
        return msg 

    def ParseInsecureMsg( self, msgRaw, expectedMsgType = MsgType.RESPONSE_ENCRYPTED_MSG ):
        curretPosition  = 0;
        msgLength        = struct.unpack( "H", msgRaw[ curretPosition:curretPosition + SIZE_OF_UINT16_T ] )[0]
        curretPosition += SIZE_OF_UINT16_T;
        
        msgtype           = struct.unpack( "H", msgRaw[ curretPosition:curretPosition + SIZE_OF_UINT16_T ] )[0]
        curretPosition += SIZE_OF_UINT16_T;        
        self.VerifyEqual( msgtype, expectedMsgType, errMsg="value = %d, instead of expected %d" % ( msgtype, MsgType.RESPONSE_ENCRYPTED_MSG ))

        msg = msgRaw[ curretPosition : ]
        # if expectedMsgType == MsgType.RESPONSE_ENCRYPTED_MSG:
        #     return self.ParseEncryptedMsg( msg )
        # #else    
        return msg 

    def PingSSM( self ):
        self.log.debug( "PingSSM" )
        if self.IsConnected is False:
            raise Exception( "Not connected to SSM" )

        PAYLOAD     = 0xdeadbeef
        sentMsgSize = self.SendPingMsg( PAYLOAD )

        #get reply:
        msgRaw    = self.ReadMsgFromSocket()
        secureMsg = self.ParseMsg( msgRaw )
    
        self.VerifyEqual( secureMsg[ 'Type' ], SecureMsgType.PING, errMsg="secure message type = 0x%x, instead of expected 0x%x" % ( secureMsg[ 'Type' ], SecureMsgType.PING ))        
        
        pingPayload = struct.unpack( "I", secureMsg[ 'Body' ] )[ 0 ]
        self.VerifyEqual( secureMsg[ 'Type' ], SecureMsgType.PING, errMsg="ping payload = 0x%x, instead of expected 0x%x" % ( PAYLOAD, pingPayload ))        

    def SendAllowUSerRegistrationRequest( self, userID, allowedServices ):
        msg     = struct.pack( "H", MsgType.REQUEST_ENCRYPTED_MSG )
        msg     += self.BuilAllowUserRegistrationMsg( userID, allowedServices )

        #Attach totalLen as PREFIX:
        msgSize = len( msg ) + SIZE_OF_TOTAL_LEN
        msg     = struct.pack( "H", msgSize) + msg

        self.ssmSocket.send( msg )

    def AllowUserRegistration( self, userPublicKey, allowedServices = ALLOW_ALL_SERVICES ):
        self.log.debug( "AllowUserRegistration" )
        if self.IsConnected is False:
            raise Exception( "Not connected to SSM" )

        userID  = self.cryptoWrapper.SHA256( userPublicKey )
        self.SendAllowUSerRegistrationRequest( userID, allowedServices ) 

        #get reply:
        msgRaw         = self.ReadMsgFromSocket()
        secureMsg     = self.ParseMsg( msgRaw )

        self.VerifySecureMsgType( secureMsg, SecureMsgType.ALLOW_USER_REGISTRATION_RESPONSE )

        identityToken = self.cryptoWrapper.Rijndael128_CMAC( userID, self.key_MK )

        return identityToken

    def SendGetSSMProofOfIDentity( self ):
        msg          = struct.pack( "H", MsgType.REQUEST_ENCRYPTED_MSG )
        msgToEncrypt = struct.pack( "H", SecureMsgType.PROVE_SSM_IDENTITY_REQUEST )
        msg          += self.CreateEncryptedMsg( msgToEncrypt )

        #Attach totalLen as PREFIX:
        msgSize = len( msg ) + SIZE_OF_TOTAL_LEN
        msg     = struct.pack( "H", msgSize) + msg

        self.ssmSocket.send( msg )

    def GetSSMProofOfIDentity( self ):
        self.log.debug( "GetSSMProofOfIDentity" )
        if self.IsConnected is False:
            raise Exception( "Not connected to SSM" )

        self.SendGetSSMProofOfIDentity()

        #get reply:
        msgRaw         = self.ReadMsgFromSocket()
        secureMsg     = self.ParseMsg( msgRaw )

        self.VerifySecureMsgType( secureMsg, SecureMsgType.PROVE_SSM_IDENTITY_RESPONSE )

        ssmProofOfIdentity = secureMsg[ 'Body' ]
        return ssmProofOfIdentity

    def BuildGenerateRSAKeyPairMsg( self, keySizeInBits, publicExponent ):
        RSA_KEY_ATTRIBUTE_CAN_SIGN = 0x00000001

        # typedef struct __attribute__((__packed__)) 
        # {

        #     RSAKeyAttributes    attributes;
        #     time_t              creationTimestamp;      // Time of creation, provided by the remote client, 
        #                                                 // as local time of the server cannot be trusted.
        #     uint16_t            modulusBits;
        #     uint16_t            publicExponentSize;
        #     uint8_t             publicExponent[];       // A buffer representing LibreSSL BigNum, created by using BN_bn2bin 
        # } GenerateKeyPairMsg;

        publicExponentAsBigNumber = self.libreSSL.BigNumber( publicExponent )
        publicExponentAsBuffer       = self.libreSSL.BN_bn2bin( publicExponentAsBigNumber )

        msgToEncrypt = struct.pack( "H", SecureMsgType.RSA_GENERATE_KEY_PAIR_REQUEST )
        msgToEncrypt += struct.pack( "Q", RSA_KEY_ATTRIBUTE_CAN_SIGN )
        msgToEncrypt += struct.pack( "Q", int( time.time() ) )
        msgToEncrypt += struct.pack( "H", keySizeInBits )
        msgToEncrypt += struct.pack( "H", len( publicExponentAsBuffer ) )
        msgToEncrypt += publicExponentAsBuffer
        
        return  self.CreateEncryptedMsg( msgToEncrypt )

    def BuilAllowUserRegistrationMsg( self, userID, allowedServices ):
        # typedef struct __attribute__((__packed__)) 
        # {
        #     sgx_sha256_hash_t userID;
        # } UserID;

        # typedef bool AllowedServicesMap[ NUM_SERVICES ];

        # typedef struct __attribute__((__packed__)) 
        # {
        #     UserID userID;
        #     AllowedServicesMap allowedServicesMap;
        # } UserPermissions;

        # typedef UserPermissions AllowUserRegistrationMsg;


        msgToEncrypt = struct.pack( "H", SecureMsgType.ALLOW_USER_REGISTRATION_REQUEST )
        msgToEncrypt += userID

        C_BOOL_TRUE  = b"\x01"
        C_BOOL_FALSE = b"\x00"
        for isServiceAllowed in allowedServices:
            if isServiceAllowed:
                msgToEncrypt += C_BOOL_TRUE
            else:
                msgToEncrypt += C_BOOL_FALSE

        return self.CreateEncryptedMsg( msgToEncrypt )

    def DeriveKey( self, label, context, sourceKey ):
        # Key derivation data,  as officially defined in NIST SP 800-108, and in "include/types.hpp"
        keyDerivationBuffer  = b"\x01"                                             #counter
        keyDerivationBuffer += label                                              #label  -Token Key (TK)
        keyDerivationBuffer += b"\x00"                                             #alwaysZero
        keyDerivationBuffer += context                                             #context
        keyDerivationBuffer += struct.pack( "H", SIZE_OF_AES_128_KEY_IN_BITS )  #lengthOfDerivedKey

        derivedKey        = self.cryptoWrapper.Rijndael128_CMAC( keyDerivationBuffer, sourceKey );

        return derivedKey

    def CreateProtectionTokenForKeyGeneration( self, ssmChallenge ):
        self.lastTokenID += 1
        tokenID           = self.lastTokenID

        protectionSecret = os.urandom( SIZE_OF_PROTECTION_SECRET )
        token              = self.CreateProtectionToken( ssmChallenge, protectionSecret )

        self.pretectionSecrets[ tokenID ] = protectionSecret 

        return token, tokenID

    def AllowKeyUsage( self, ssmChallenge, tokenID ):
        secret = self.pretectionSecrets[ tokenID ]
        return  self.CreateProtectionToken( ssmChallenge, secret )


    def CreateProtectionToken( self, ssmChallenge, protectionSecret ):
        # typedef struct __attribute__((__packed__)) 
        # {
        #     UserID                          userID;
        #     Nonce                           userNonce;
        #     sgx_aes_gcm_128bit_tag_t        mac;
        #     ProtectionSecret                protectionSecret;
        #     // sgx_sha256_hash_t               keyRequestDigest;
        # } ProtectionToken;

        userNonce              = os.urandom( SIZE_OF_SESSION_KEY_NONCE )
        label                  = b"TK" #Token Key (TK)
        tokenKey               = self.DeriveKey( label, ssmChallenge + userNonce, self.key_MK )

        ZERO_IV               = b"\x00" * SIZE_OF_AES_GCM_IV
        NO_AAD                   = None
        encryptedSecret, mac = self.cryptoWrapper.Rijndael128GCM_Encrypt(   tokenKey, 
                                                                            bytearray( ZERO_IV ), 
                                                                            bytearray( protectionSecret ), 
                                                                            NO_AAD )

        protectionToken = self.CalcUserID()
        protectionToken += userNonce
        protectionToken += mac
        protectionToken += encryptedSecret

        return protectionToken

    def BuildSharedCustodySpec( self, ssmChallenge, password, additionalTokens ):
        # typedef struct __attribute__((__packed__)) 
        # {
        #     uint16_t            numParticipants;
        #     ProtectionToken     protectionTokens[];
        # } SharedCustodySpec;
        NUM_PARTICIPANTS  = 1 + len( additionalTokens )
        sharedCustodySpec = struct.pack( "H", NUM_PARTICIPANTS )    
        sharedCustodySpec += self.CreateProtectionToken( ssmChallenge, password )

        for token in additionalTokens:
            sharedCustodySpec += token

        return sharedCustodySpec

    def BuildGenerateECDSAKeyPairMsg( self, ssmChallenge, password, additionalTokens ):
        KEY_ATTRIBUTE_CAN_SIGN         = 0x00000001
        KEY_ATTRIBUTE_STORE_ON_DISK = 1 << 3
        KEY_PROTECTION_PASSWORD_SIZE = 16

        attributes = KEY_ATTRIBUTE_CAN_SIGN

        storeOnDisk = False
        if len( password ) > 0 :
            storeOnDisk = True
            if len( password ) != KEY_PROTECTION_PASSWORD_SIZE:
                raise RemoteSSMManagerError( "Password size must be %d" % KEY_PROTECTION_PASSWORD_SIZE )

            attributes |= KEY_ATTRIBUTE_STORE_ON_DISK

        # typedef struct __attribute__((__packed__)) 
        # {
        #     KeyAttributes       attributes;
        # } ECDSA_GenerateKeyPairMsg;
        msgToEncrypt = struct.pack( "H", SecureMsgType.ECDSA_GENERATE_KEY_PAIR_REQUEST )
        msgToEncrypt += struct.pack( "Q", attributes )
        
        if storeOnDisk:
            msgToEncrypt += self.BuildSharedCustodySpec( ssmChallenge, password, additionalTokens )

        return  self.CreateEncryptedMsg( msgToEncrypt )

    def BuildGenerateECDSAKeyPairOpenSSLMsg( self, ecc_curve_nid, ssmChallenge, password, additionalTokens ):
        KEY_ATTRIBUTE_CAN_SIGN         = 0x00000001
        KEY_ATTRIBUTE_STORE_ON_DISK = 1 << 3
        KEY_PROTECTION_PASSWORD_SIZE = 16

        attributes = KEY_ATTRIBUTE_CAN_SIGN

        storeOnDisk = False
        if len( password ) > 0 :
            raise Exception( "not imlemented" )

        # typedef struct __attribute__((__packed__)) 
        # {
        #     KeyAttributes       attributes;
            
        #     uint16_t            curveNID;
        # } ECDSA_GenerateKeyPairOpenSSLMsg;

        msgToEncrypt = struct.pack( "H", SecureMsgType.ECDSA_GENERATE_KEY_PAIR_OPENSSL_REQUEST )
        msgToEncrypt += struct.pack( "Q", attributes )
        msgToEncrypt += struct.pack( "H", ecc_curve_nid )
        
        if storeOnDisk:
            raise Exception( "not imlemented" )
            # msgToEncrypt += self.BuildSharedCustodySpec( ssmChallenge, password, additionalTokens )

        return  self.CreateEncryptedMsg( msgToEncrypt )

    def BuildGenerateAES_GCM_KeyMsg( self, AES_CMAC_KEY, keySize ):
        if AES_CMAC_KEY is True:
            KEY_ATTRIBUTE_CAN_ENCRYPT = 1 << 5    
        else:
            KEY_ATTRIBUTE_CAN_ENCRYPT = 1 << 1

        KEY_SIZE_BITS               = keySize
        # typedef struct __attribute__((__packed__)) 
        # {
        #     KeyAttributes       attributes;
        #     uint16_t            keySizeInBits;
        # } AES_GCM_GenerateKeyMsg;

        msgToEncrypt = struct.pack( "H", SecureMsgType.AES_GCM_GENERATE_KEY_REQUEST )
        msgToEncrypt += struct.pack( "Q", KEY_ATTRIBUTE_CAN_ENCRYPT )
        msgToEncrypt += struct.pack( "H", KEY_SIZE_BITS )
        
        return  self.CreateEncryptedMsg( msgToEncrypt )


    def SendGenerateRSAKeyPairRequest( self, keySizeInBits, publicExponent ):
        msg     = struct.pack( "H", MsgType.REQUEST_ENCRYPTED_MSG )
        msg     += self.BuildGenerateRSAKeyPairMsg( keySizeInBits, publicExponent )

        #Attach totalLen as PREFIX:
        msgSize = len( msg ) + SIZE_OF_TOTAL_LEN
        msg     = struct.pack( "H", msgSize) + msg

        self.ssmSocket.send( msg )

    def SendGenerateECDSAKeyPairRequest( self, ssmChallenge, password , additionalTokens ):
        msg     = struct.pack( "H", MsgType.REQUEST_ENCRYPTED_MSG )
        msg     += self.BuildGenerateECDSAKeyPairMsg( ssmChallenge, password, additionalTokens )

        #Attach totalLen as PREFIX:
        msgSize = len( msg ) + SIZE_OF_TOTAL_LEN
        msg     = struct.pack( "H", msgSize) + msg

        self.ssmSocket.send( msg )

    def SendGenerateECDSASAKeypair_OpenSSLRequest( self, ecc_curve_nid, ssmChallenge, password , additionalTokens ):
        msg     = struct.pack( "H", MsgType.REQUEST_ENCRYPTED_MSG )
        msg     += self.BuildGenerateECDSAKeyPairOpenSSLMsg( ecc_curve_nid, ssmChallenge, password, additionalTokens )

        #Attach totalLen as PREFIX:
        msgSize = len( msg ) + SIZE_OF_TOTAL_LEN
        msg     = struct.pack( "H", msgSize) + msg

        self.ssmSocket.send( msg )

    def SendEncryptedMsg( self, payload ):
        msg     = struct.pack( "H", MsgType.REQUEST_ENCRYPTED_MSG )
        msg     += payload

        #Attach totalLen as PREFIX:
        msgSize = len( msg ) + SIZE_OF_TOTAL_LEN
        msg     = struct.pack( "H", msgSize) + msg

        self.ssmSocket.send( msg )

    def SendSyncSessionMsg( self ):
        msg     = struct.pack( "H", MsgType.REQUEST_SYNC )

        #Attach totalLen as PREFIX:
        msgSize = len( msg ) + SIZE_OF_TOTAL_LEN
        msg     = struct.pack( "H", msgSize) + msg

        self.ssmSocket.send( msg )


    def SendGenerate_AES_GCM_Request( self,AES_CMAC_KEY, keySize ):
        msg     = struct.pack( "H", MsgType.REQUEST_ENCRYPTED_MSG )
        msg     += self.BuildGenerateAES_GCM_KeyMsg( AES_CMAC_KEY, keySize )

        #Attach totalLen as PREFIX:
        msgSize = len( msg ) + SIZE_OF_TOTAL_LEN
        msg     = struct.pack( "H", msgSize) + msg

        self.ssmSocket.send( msg )

    def ParsGenerateRSAKeyPairResponse( self, genKairPairResponse ):
        # typedef struct __attribute__((__packed__)) 
        # {
        #     uint64_t handle;
        #     uint16_t publicKeySize;
        #     uint16_t certificateSize;
        #     uint8_t  publicKeyAndCertificate[];
        # } RSAGenerateKeyPairResponseMsg;

        curretPosition  = 0;
        keyHandle       = struct.unpack( "Q", genKairPairResponse[ curretPosition:curretPosition + SIZE_OF_UINT64_T ] )[0]        
        curretPosition += SIZE_OF_UINT64_T

        publicKeySize   = struct.unpack( "H", genKairPairResponse[ curretPosition:curretPosition + SIZE_OF_UINT16_T ] )[0]        
        curretPosition += SIZE_OF_UINT16_T

        certificateSize = struct.unpack( "H", genKairPairResponse[ curretPosition:curretPosition + SIZE_OF_UINT16_T ] )[0]        
        curretPosition += SIZE_OF_UINT16_T

        expetedTotalSize = SIZE_OF_UINT64_T + SIZE_OF_UINT16_T*2 + publicKeySize + certificateSize
        self.VerifyEqual( len( genKairPairResponse ), expetedTotalSize, errMsg="genKairPairResponse size = %d, instead of expected %d" % ( len( genKairPairResponse ), expetedTotalSize ) )

        publicKeyAsDER  = genKairPairResponse[ curretPosition:curretPosition + publicKeySize ]
        curretPosition += publicKeySize
        expectedHandle = self.cryptoWrapper.SHA256( publicKeyAsDER )[ 0:SIZE_OF_UINT64_T ]
        expectedHandle = struct.unpack( "Q", expectedHandle )[0]
        self.VerifyEqual( keyHandle, expectedHandle, errMsg="keyHandle = 0x%016x, instead of expected 0x%016x" % ( keyHandle, expectedHandle ) )

        certificate    = genKairPairResponse[ curretPosition:curretPosition + certificateSize ]

        key = {}
        key[ 'handle'           ] = keyHandle
        key[ 'publicKeyAsDER' ] = publicKeyAsDER
        key[ 'certificate'    ] = certificate

        return key

    def ParsGenerateECDSAKeyPairResponse( self, genKeyPairResponse ):
        # typedef struct __attribute__((__packed__)) 
        # {
        #     uint64_t handle;
        #     sgx_ec256_public_t publicKey;
        # } ECDSA_GenerateKeyPairResponseMsg;

        curretPosition  = 0;
        keyHandle       = struct.unpack( "Q", genKeyPairResponse[ curretPosition:curretPosition + SIZE_OF_UINT64_T ] )[0]        
        curretPosition += SIZE_OF_UINT64_T

        publicKey   =  genKeyPairResponse[ curretPosition:curretPosition + SIZE_OF_EC256_PUBLIC_KEY ] 
        curretPosition += SIZE_OF_EC256_PUBLIC_KEY
        expetedTotalSize = SIZE_OF_UINT64_T + SIZE_OF_EC256_PUBLIC_KEY
        self.VerifyEqual( len( genKeyPairResponse ), expetedTotalSize, errMsg="genKeyPairResponse size = %d, instead of expected %d" % ( len( genKeyPairResponse ), expetedTotalSize ) )

        expectedHandle = self.cryptoWrapper.SHA256( publicKey )[ 0:SIZE_OF_UINT64_T ]
        expectedHandle = struct.unpack( "Q", expectedHandle )[0]
        self.VerifyEqual( keyHandle, expectedHandle, errMsg="keyHandle = 0x%016x, instead of expected 0x%016x" % ( keyHandle, expectedHandle ) )

        key = {}
        key[ 'handle'    ] = keyHandle
        key[ 'publicKey' ] = publicKey

        return key

    def ParsGenerateECDSAKeyPairOpenSSLResponse( self, genKairPairResponse ):
        # typedef struct __attribute__((__packed__)) 
        # {
        #     uint64_t handle;
        #     uint16_t publicKeySize;    
        #     uint8_t  publicKey[];
        # } ECDSA_GenerateKeyPairOpenSSLResponseMsg;

        curretPosition  = 0;
        keyHandle       = struct.unpack( "Q", genKairPairResponse[ curretPosition:curretPosition + SIZE_OF_UINT64_T ] )[0]        
        curretPosition += SIZE_OF_UINT64_T

        publicKeySize   = struct.unpack( "H", genKairPairResponse[ curretPosition:curretPosition + SIZE_OF_UINT16_T ] )[0]        
        curretPosition += SIZE_OF_UINT16_T

        expetedTotalSize = SIZE_OF_UINT64_T + SIZE_OF_UINT16_T + publicKeySize 
        self.VerifyEqual( len( genKairPairResponse ), expetedTotalSize, errMsg="genKairPairResponse size = %d, instead of expected %d" % ( len( genKairPairResponse ), expetedTotalSize ) )

        publicKeyAsDER  = genKairPairResponse[ curretPosition:curretPosition + publicKeySize ]
        curretPosition += publicKeySize
        expectedHandle = self.cryptoWrapper.SHA256( publicKeyAsDER )[ 0:SIZE_OF_UINT64_T ]
        expectedHandle = struct.unpack( "Q", expectedHandle )[0]
        self.VerifyEqual( keyHandle, expectedHandle, errMsg="keyHandle = 0x%016x, instead of expected 0x%016x" % ( keyHandle, expectedHandle ) )

        key = {}
        key[ 'handle'           ] = keyHandle
        key[ 'publicKeyAsDER' ] = publicKeyAsDER

        return key

    def ParsGenerateAES_GCM_KeyResponse( self, genKeyResponse ):
        # typedef struct __attribute__((__packed__)) 
        # {
        #     uint64_t handle;
        # } AES_GCM_GenerateKeyResponseMsg;

        curretPosition  = 0;
        keyHandle       = struct.unpack( "Q", genKeyResponse[ curretPosition:curretPosition + SIZE_OF_UINT64_T ] )[0]        
        curretPosition += SIZE_OF_UINT64_T

        key = {}
        key[ 'handle'    ] = keyHandle

        return key

    def GenerateRSAKeyPair( self, keySizeInBits, publicExponent ):
        self.log.debug( "GenerateRSAKeyPair" )
        if self.IsConnected is False:
            raise Exception( "Not connected to SSM" )

        self.SendGenerateRSAKeyPairRequest( keySizeInBits, publicExponent )

        #get reply:
        msgRaw         = self.ReadMsgFromSocket()
        secureMsg     = self.ParseMsg( msgRaw )

        self.VerifyEqual( secureMsg[ 'Type' ], SecureMsgType.RSA_GENERATE_KEY_PAIR_RESPONSE, errMsg="secure message type = 0x%x, instead of expected 0x%x" % ( secureMsg[ 'Type' ] , SecureMsgType.RSA_GENERATE_KEY_PAIR_RESPONSE ))        

        publicKey = self.ParsGenerateRSAKeyPairResponse( secureMsg[ 'Body' ] )        

        return publicKey

    def GenerateECDSAKeyPair( self, ssmChallenge = '', password = '', additionalTokens = [] ):
        self.log.debug( "GenerateECDSAKeyPair" )
        if self.IsConnected is False:
            raise Exception( "Not connected to SSM" )

        self.VerifyEqual( len( ssmChallenge ), len( password ), "len( ssmChallenge ) should be == len( password ), but %d != %d" % ( len( ssmChallenge ), len( password ) ) )

        self.SendGenerateECDSAKeyPairRequest( ssmChallenge, password, additionalTokens )

        #get reply:
        msgRaw    = self.ReadMsgFromSocket()
        secureMsg = self.ParseMsg( msgRaw )
    
        self.VerifyEqual( secureMsg[ 'Type' ], SecureMsgType.ECDSA_GENERATE_KEY_PAIR_RESPONSE, errMsg="secure message type = 0x%x, instead of expected 0x%x" % ( secureMsg[ 'Type' ] , SecureMsgType.RSA_GENERATE_KEY_PAIR_RESPONSE ))        

        publicKey = self.ParsGenerateECDSAKeyPairResponse( secureMsg[ 'Body' ] ) 

        return publicKey

    def GenerateECDSASAKeypair_OpenSSL( self, ecc_curve_nid, ssmChallenge = '', password = '', additionalTokens = [] ):
        self.log.debug( "GenerateECDSASAKeypair_OpenSSL" )
        if self.IsConnected is False:
            raise Exception( "Not connected to SSM" )

        self.VerifyEqual( len( ssmChallenge ), len( password ), "len( ssmChallenge ) should be == len( password ), but %d != %d" % ( len( ssmChallenge ), len( password ) ) )

        self.SendGenerateECDSASAKeypair_OpenSSLRequest( ecc_curve_nid, ssmChallenge, password, additionalTokens )

        #get reply:
        msgRaw    = self.ReadMsgFromSocket()
        secureMsg = self.ParseMsg( msgRaw )
    
        self.VerifyEqual( secureMsg[ 'Type' ], SecureMsgType.ECDSA_GENERATE_KEY_PAIR_OPENSSL_RESPONSE, errMsg="secure message type = 0x%x, instead of expected 0x%x" % ( secureMsg[ 'Type' ] , SecureMsgType.RSA_GENERATE_KEY_PAIR_RESPONSE ))        

        publicKey = self.ParsGenerateECDSAKeyPairOpenSSLResponse( secureMsg[ 'Body' ] ) 
        publicKey[ "Curve" ] = ecc_curve_nid;

        return publicKey

    def BuildArmKeyRequest( self, keyHandle, ssmChallenge, password, additionalTokens = []  ):
        # typedef struct __attribute__((__packed__)) 
        # {
        #     uint64_t            keyHandle;
        #     SharedCustodySpec   sharedCustodySpec;
        # } ArmKeyRequest;
  
        msgToEncrypt = struct.pack( "H", SecureMsgType.ARM_KEY_REQUEST )
        msgToEncrypt += struct.pack( "Q", keyHandle )
        msgToEncrypt += self.BuildSharedCustodySpec( ssmChallenge, password, additionalTokens )
        
        return  self.CreateEncryptedMsg( msgToEncrypt )

    def BuildImportRSAKeyRequest( self, privateKeyAsDER ):
        # typedef struct __attribute__((__packed__)) 
        # {
        #     uint16_t privateKeySize;
        #     uint8_t  privateKeyAsDER[];
        # } ImportRSAKeyMsg;
        msgToEncrypt = struct.pack( "H", SecureMsgType.IMPORT_RSA_KEY_REQUEST )
        msgToEncrypt += struct.pack( "H", len( privateKeyAsDER ) )
        msgToEncrypt += privateKeyAsDER
        
        return  self.CreateEncryptedMsg( msgToEncrypt )

    def BuildGetConfigID( self ):
        msgToEncrypt = struct.pack( "H", SecureMsgType.GET_CONFIG_ID_REQUEST )
        
        return  self.CreateEncryptedMsg( msgToEncrypt )

    def BuildGetChallengeRequest( self ):
        msgToEncrypt = struct.pack( "H", SecureMsgType.GET_CHALLENGE_REQUEST )
        
        return  self.CreateEncryptedMsg( msgToEncrypt )

    def ArmKey( self, keyHandle, ssmChallenge, password, additionalTokens = []  ):
        self.log.debug( "ArmKey" )
        if self.IsConnected is False:
            raise Exception( "Not connected to SSM" )

        self.SendEncryptedMsg( self.BuildArmKeyRequest( keyHandle, ssmChallenge, password, additionalTokens ) )
        
        #get reply:
        msgRaw    = self.ReadMsgFromSocket()
        secureMsg = self.ParseMsg( msgRaw )
    
        self.VerifySecureMsgType( secureMsg, SecureMsgType.ARM_KEY_RESPONSE )

    def SyncSecureSession( self ):
        self.log.debug( "SyncSecureSession" )
        if self.IsConnected is False:
            raise Exception( "Not connected to SSM" )

        self.SendSyncSessionMsg()

        #get reply:
        msgRaw    = self.ReadMsgFromSocket()
        msgType   = self.GetMsgType( msgRaw )
        self.VerifyEqual(     msgType, 
                            MsgType.RESPONSE_SYNC, 
                            errMsg="value = %d, instead of expected %d" % ( msgType, MsgType.RESPONSE_SYNC ))


        msgBodyOffset = SIZE_OF_UINT16_T * 2
        lastSessionMsgCounter = struct.unpack( "Q", msgRaw[ msgBodyOffset : ] )[ 0 ]
        if lastSessionMsgCounter < self.sessionEncryptMsgCounter:
            raise RemoteSSMManagerError( "lastSessionMsgCounter < self. sessionMsgCounter (%d < %d)" % ( lastSessionMsgCounter, self.sessionEncryptMsgCounter ))

        self.log.info( "Adjusting sessionMsgCounter %d --> %d" % ( self.sessionEncryptMsgCounter, lastSessionMsgCounter ))
        self.sessionEncryptMsgCounter = lastSessionMsgCounter
        self.sessionDecryptMsgCounter = lastSessionMsgCounter

    def GetChallenge( self ):
        self.log.debug( "GetChallenge" )
        if self.IsConnected is False:
            raise Exception( "Not connected to SSM" )

        self.SendEncryptedMsg( self.BuildGetChallengeRequest() )
        
        #get reply:
        msgRaw    = self.ReadMsgFromSocket()
        secureMsg = self.ParseMsg( msgRaw )
    
        self.VerifySecureMsgType( secureMsg, SecureMsgType.GET_CHALLENGE_RESPONSE )
        return secureMsg[ 'Body' ]

    def GetConfigurationID( self ):
        self.log.debug( "GetConfigurationID" )
        if self.IsConnected is False:
            raise Exception( "Not connected to SSM" )

        self.SendEncryptedMsg( self.BuildGetConfigID() )
        
        #get reply:
        msgRaw    = self.ReadMsgFromSocket()
        secureMsg = self.ParseMsg( msgRaw )
    
        self.VerifySecureMsgType( secureMsg, SecureMsgType.GET_CONFIG_ID_RESPONSE )
        return secureMsg[ 'Body' ]


    def Generate_AES_GCM_Key( self, keySize, AES_CMAC_KEY = False ):
        self.log.debug( "Generate_AES_GCM_Key" )
        if self.IsConnected is False:
            raise Exception( "Not connected to SSM" )

        self.SendGenerate_AES_GCM_Request( AES_CMAC_KEY, keySize )

        #get reply:
        msgRaw    = self.ReadMsgFromSocket()
        secureMsg = self.ParseMsg( msgRaw )
        
        self.VerifyEqual( secureMsg[ 'Type' ], SecureMsgType.AES_GCM_GENERATE_KEY_RESPONSE, errMsg="secure message type = 0x%x, instead of expected 0x%x" % ( secureMsg[ 'Type' ] , SecureMsgType.RSA_GENERATE_KEY_PAIR_RESPONSE ))        

        key = self.ParsGenerateAES_GCM_KeyResponse( secureMsg[ 'Body' ] ) 

        return key

    def BuildEncryptedDataRequest( self, payload, keyHandle, requestType, requestPrefix ):
        # typedef struct __attribute__((__packed__)) 
        # {
        #     uint64_t keyHandle;
        #     uint16_t dataSize;
        #     uint8_t  data[];
        # } ProcessDataMsg;

        msgToEncrypt  = struct.pack( "H", requestType )
        msgToEncrypt += requestPrefix
        msgToEncrypt += struct.pack( "Q", keyHandle )
        msgToEncrypt += struct.pack( "H", len( payload ) )
        msgToEncrypt += payload

        return  self.CreateEncryptedMsg( msgToEncrypt )

    def SendDataRequest( self, payload, keyHandle, requestType, requestPrefix = b'' ):
        msg     = struct.pack( "H", MsgType.REQUEST_ENCRYPTED_MSG )
        msg     += self.BuildEncryptedDataRequest( payload, keyHandle, requestType, requestPrefix )

        #Attach totalLen as PREFIX:
        msgSize = len( msg ) + SIZE_OF_TOTAL_LEN
        msg     = struct.pack( "H", msgSize) + msg

        self.ssmSocket.send( msg )


    def ParseRSASignature( self, signResponse ):
        curretPosition = 0
        sigLength        = struct.unpack( "H", signResponse[ curretPosition:curretPosition + SIZE_OF_UINT16_T ] )[0]
        curretPosition += SIZE_OF_UINT16_T;

        signature = signResponse[ curretPosition: ]
        self.VerifyEqual( sigLength, len( signature ) , errMsg="signature len = %d, instead of expected %d" % ( sigLength, len( signature ) ) )

        return signature

    def ImportRSAKey( self, privateKeyAsDER ):
        self.SendEncryptedMsg( self.BuildImportRSAKeyRequest( privateKeyAsDER ) )
        
        #get reply:
        msgRaw    = self.ReadMsgFromSocket()
        secureMsg = self.ParseMsg( msgRaw )
    
        self.VerifySecureMsgType( secureMsg, SecureMsgType.IMPORT_RSA_KEY_RESPONSE )
        print( "secureMsg = %s" % secureMsg )
        keyHandle = struct.unpack( "Q", secureMsg[ 'Body' ] )[ 0 ]

        return keyHandle

    
    def EncryptAES_GCM_parseTagIVCipher( self, encryptResponse ):
        # typedef struct __attribute__((__packed__)) 
        # {
        #     AES_GCM_IV                  iv;
        #     sgx_aes_gcm_128bit_tag_t    tag;
        #     uint16_t                    cipherSize;
        #     uint8_t                     cipherText[];
        # } AES_GCM_EncryptResponseMsg;        

        encryptedText = {}

        curretPosition = 0
        encryptedText[ 'IV']  =  encryptResponse[ curretPosition:curretPosition + SIZE_OF_AES_GCM_IV ] 
        curretPosition          += SIZE_OF_AES_GCM_IV;

        encryptedText[ 'MAC'] =  encryptResponse[ curretPosition:curretPosition + SIZE_OF_AES_GCM_MAC ] 
        curretPosition          += SIZE_OF_AES_GCM_MAC;

        cipherSize              = struct.unpack( "H", encryptResponse[ curretPosition:curretPosition + SIZE_OF_UINT16_T ] )[0]
        curretPosition          += SIZE_OF_UINT16_T;

        encryptedText[ 'ciphertext' ] = encryptResponse[ curretPosition: ]
        self.VerifyEqual( cipherSize, len( encryptedText[ 'ciphertext' ] ) , errMsg="cipherSize len = %d, instead of expected %d" % ( len( encryptedText[ 'ciphertext' ] ), cipherSize ) )

        return encryptedText



    # def EncryptAES_GCM_parseResponse( self, msgRaw ):
    #     curretPosition  = 0;
    #     msgLength        = struct.unpack( "H", msgRaw[ curretPosition:curretPosition + SIZE_OF_UINT16_T ] )[0]
    #     curretPosition += SIZE_OF_UINT16_T;

    #     msgtype           = struct.unpack( "H", msgRaw[ curretPosition:curretPosition + SIZE_OF_UINT16_T ] )[0]
    #     curretPosition += SIZE_OF_UINT16_T;        
    #     self.VerifyEqual( msgtype, MsgType.RESPONSE_ENCRYPTED_MSG, errMsg="value = %d, instead of expected %d" % ( msgtype, MsgType.RESPONSE_ENCRYPTED_MSG ))

    #     encryptedMsg       = msgRaw[ curretPosition : ]
    #     secureMsg         = self.ParseEncryptedMsg( encryptedMsg )
    #     self.VerifyEqual( secureMsg[ 'Type' ], SecureMsgType.AES_GCM_ENCRYPT_RESPONSE, errMsg="secure message type = 0x%x, instead of expected 0x%x" % ( secureMsg[ 'Type' ], SecureMsgType.RSA_SIGN_RESPONSE ))        
        
    #     return self.EncryptAES_GCM_parseResponse_getTagIVCipher( secureMsg[ 'Body' ]  )        


    def DecryptAES_GCM_parseResponse( self, decryptResponse ):
        # typedef struct __attribute__((__packed__)) 
        # {
        #     uint16_t plainSize;
        #     uint8_t  plainText[];
        # } AES_GCM_DecryptResponseMsg;
        curretPosition        = 0;
        plainSize              = struct.unpack( "H", decryptResponse[ curretPosition:curretPosition + SIZE_OF_UINT16_T ] )[0]
        curretPosition          += SIZE_OF_UINT16_T;

        plainText = decryptResponse[ curretPosition: ]
        self.VerifyEqual( plainSize, len( plainText ) , errMsg="cipherSize len = %d, instead of expected %d" % ( plainSize, len( plainText ) ) )
        
        return plainText

    def SignRSA( self, dataToSign, keyHandle ):
        self.log.debug( "SignRSA" )
        if self.IsConnected is False:
            raise Exception( "Not connected to SSM" )

        self.SendDataRequest(     dataToSign, 
                                keyHandle, 
                                SecureMsgType.RSA_SIGN_REQUEST )

        #get reply:
        msgRaw    = self.ReadMsgFromSocket()
        secureMsg = self.ParseMsg( msgRaw )
        signature = self.ParseRSASignature( secureMsg[ 'Body' ] )

        return signature
    #     # pprint.pprint( signature )

    #     return signature

        # return self.SignRSA_parseResponse( msgRaw )
            
    def SignECDSA( self, dataToSign, keyHandle ):
        self.log.debug( "SignECDSA" )
        if self.IsConnected is False:
            raise Exception( "Not connected to SSM" )

        self.SendDataRequest(     dataToSign, 
                                keyHandle, 
                                SecureMsgType.ECDSA_SIGN_REQUEST )

        #get reply:
        msgRaw         = self.ReadMsgFromSocket()
        secureMsg     = self.ParseMsg( msgRaw )
        signature     = secureMsg[ 'Body' ] 
        
        self.VerifySecureMsgType( secureMsg, SecureMsgType.ECDSA_SIGN_RESPONSE )
        self.VerifyEqual( SIZE_OF_EC256_SIGNATURE, len( signature ) , errMsg="signature len = %d, instead of expected %d" % ( len( signature ), SIZE_OF_EC256_SIGNATURE) )
        
        return signature
        # return self.SignECDSA_parseResponse( msgRaw )

    def SignECDSAOpenSSL( self, dataToSign, keyHandle ):
        self.log.debug( "SignECDSAOpenSSL" )
        if self.IsConnected is False:
            raise Exception( "Not connected to SSM" )

        self.SendDataRequest(   dataToSign, 
                                keyHandle, 
                                SecureMsgType.ECDSA_SIGN_OPENSSL_REQUEST )

        #get reply:
        msgRaw    = self.ReadMsgFromSocket()
        secureMsg = self.ParseMsg( msgRaw )
        signature = self.ParseRSASignature( secureMsg[ 'Body' ] )
        
        self.VerifySecureMsgType( secureMsg, SecureMsgType.ECDSA_SIGN_OPENSSL_RESPONSE )
        # self.VerifyEqual( SIZE_OF_EC256_SIGNATURE, len( signature ) , errMsg="signature len = %d, instead of expected %d" % ( len( signature ), SIZE_OF_EC256_SIGNATURE) )
        
        return signature

    def AES_CMAC( self, dataToMac, keyHandle ):
        self.log.debug( "AES_CMAC" )
        if self.IsConnected is False:
            raise Exception( "Not connected to SSM" )

        self.SendDataRequest(     dataToMac, 
                                keyHandle, 
                                SecureMsgType.AES_CMAC_REQUEST )
        #get reply:
        msgRaw    = self.ReadMsgFromSocket()
        secureMsg = self.ParseMsg( msgRaw )
        self.VerifyEqual( secureMsg[ 'Type' ], SecureMsgType.AES_CMAC_RESPONSE, errMsg="secure message type = 0x%x, instead of expected 0x%x" % ( secureMsg[ 'Type' ], SecureMsgType.AES_GCM_ENCRYPT_RESPONSE ))        
        
        cmac = secureMsg[ 'Body' ]
        return cmac    

    def EncryptAES_GCM( self, dataToEncrypt, keyHandle ):
        self.log.debug( "EncryptAES_GCM" )
        if self.IsConnected is False:
            raise Exception( "Not connected to SSM" )

        self.SendDataRequest(     dataToEncrypt, 
                                keyHandle, 
                                SecureMsgType.AES_GCM_ENCRYPT_REQUEST )
        #get reply:
        msgRaw    = self.ReadMsgFromSocket()
        secureMsg = self.ParseMsg( msgRaw )
        self.VerifyEqual( secureMsg[ 'Type' ], SecureMsgType.AES_GCM_ENCRYPT_RESPONSE, errMsg="secure message type = 0x%x, instead of expected 0x%x" % ( secureMsg[ 'Type' ], SecureMsgType.AES_GCM_ENCRYPT_RESPONSE ))        
        
        return self.EncryptAES_GCM_parseTagIVCipher( secureMsg[ 'Body' ]  )        


    def VerifySecureMsgType( self, secureMsg, expectedType ):
        if secureMsg[ 'Type'] == SecureMsgType.ERROR_MSG:
            msgBody         = secureMsg[ 'Body' ]
            curretPosition  = 0
            errorCode        = struct.unpack( "I", msgBody[ curretPosition:curretPosition + SIZE_OF_UINT32_T ] )[0]

            err         = RemoteSSMManagerError( "Secure message indicates failure. Error code = 0x%x" % errorCode )
            err.errCode = errorCode

            raise err

        self.VerifyEqual( secureMsg[ 'Type' ], expectedType, errMsg="secure message type = 0x%x, instead of expected 0x%x" % ( secureMsg[ 'Type' ], expectedType ))        

    def DecryptAES_GCM( self, cipherText, keyHandle ):
        self.log.debug( "DecryptAES_GCM" )
        if self.IsConnected is False:
            raise Exception( "Not connected to SSM" )

        requestPrefix = cipherText[ 'IV' ] + cipherText[ 'MAC' ]
        self.SendDataRequest(     cipherText[ 'ciphertext' ], 
                                keyHandle, 
                                SecureMsgType.AES_GCM_DECRYPT_REQUEST,
                                requestPrefix )
        #get reply:
        msgRaw    = self.ReadMsgFromSocket()
        secureMsg = self.ParseMsg( msgRaw )
        self.VerifySecureMsgType( secureMsg, SecureMsgType.AES_GCM_DECRYPT_RESPONSE )
        self.VerifyEqual( secureMsg[ 'Type' ], SecureMsgType.AES_GCM_DECRYPT_RESPONSE, errMsg="secure message type = 0x%x, instead of expected 0x%x" % ( secureMsg[ 'Type' ], SecureMsgType.AES_GCM_DECRYPT_RESPONSE ))        
        
        return self.DecryptAES_GCM_parseResponse( secureMsg[ 'Body' ] )

    def VerifyRSASignature( self, dataToSign, signature, publicKeyAsDER ):
        publicKey = self.libreSSL.ParsePublicKeyAsDER( publicKeyAsDER )
        self.libreSSL.VerifyRSASignature( dataToSign, signature, publicKey )

    def VerifyECDSA_OpenSSL_Signature( self, dataToSign, signature, publicKeyAsDER ):
        publicKey = self.libreSSL.ParsePublicKeyAsDER( publicKeyAsDER )
        print( "publicKey = %s" % publicKey )
        self.libreSSL.VerifyECDSA_OpenSSL_Signature( dataToSign, signature, publicKey )

    def VerifyECDSASignature( self, dataToSign, signature, publicKey ):
        if( False == self.cryptoWrapper.VerifyECDSASignature(     dataToSign, 
                                                                signature, 
                                                                publicKey ) ):
            raise RemoteSSMManagerError( "Invalid ECDSA signature")

    def SaveMasterKeys( self ):
        masterKeys = {}
        masterKeys[ 'SMK'        ] = self.key_SMK
        masterKeys[ 'SK'          ] = self.key_SK 
        masterKeys[ 'VK'          ] = self.key_VK 
        masterKeys[ 'MK'          ] = self.key_MK 
        masterKeys[ 'publicKey' ] = bytearray( self.publicKey )
        
        with open( KEY_STORE_FILE_PATH, "wb" ) as keyStoreFile:
            pickle.dump( masterKeys, keyStoreFile )

    def LoadMasterKeys( self ):
        with open( KEY_STORE_FILE_PATH, "rb" ) as keyStoreFile:
            masterKeys = pickle.load( keyStoreFile )

        self.key_SMK   = masterKeys[ 'SMK' ] 
        self.key_SK    = masterKeys[ 'SK' ]  
        self.key_VK    = masterKeys[ 'VK' ]  
        self.key_MK    = masterKeys[ 'MK' ]  
        self.publicKey = masterKeys[ 'publicKey' ]

    def ReadBytes( self, numBytesToRead, timeout = 5 ):
        msgRaw       = b''

        startTime    = time.time()
        while( len(msgRaw) < numBytesToRead):
            try:
                msgRaw       += self.ssmSocket.recv( numBytesToRead - len(msgRaw) )
            except socket.error as e:
                
                # time.sleep(0.0001)
                # self.misreadCounter += 1
                # if self.misreadCounter % 100 == 0:
                #     print( "self.misreadCounter = %d" % self.misreadCounter)
                err = e.args[0]
                if err == errno.EAGAIN or err == errno.EWOULDBLOCK:
                    # print( 'No data available %f' % (time.time() - startTime) )
                    if ( time.time() - startTime ) > timeout :
                        self.log.error( "Timeout expired (%f)" % timeout )
                        raise Exception( "Timeout expired" )
                    else:
                        # time.sleep(0.001)
                        continue
                else:
                    raise e

        return  msgRaw

    def ReadMsgFromSocket( self ):
        rawSize      = self.ReadBytes( SIZE_OF_TOTAL_LEN )
        msgLength    = struct.unpack( "H", rawSize )[0]
        self.log.debug( "Message size = %d" % msgLength )
        msgRaw       = self.ReadBytes( msgLength - SIZE_OF_TOTAL_LEN )
        msg           = rawSize + msgRaw

        return msg

    def CreateCertificateFile( self, key, filePath ):
        self.log.debug( "CreateCertificateFile: saving certificate to %s" % filePath )
        encodedPublicKey   = base64.b64encode( key[ 'publicKeyAsDER' ] ).decode()
        encodedCertificate = base64.b64encode( key[ 'certificate' ] ).decode()

        certFile = open( filePath, "w" )
        certFile.write( "-----BEGIN PUBLIC KEY-----" )
        for i in range( len( encodedPublicKey ) ):
            if i % 64 == 0:
                certFile.write( "\n" )
            certFile.write( encodedPublicKey[ i ] )
        certFile.write( "\n-----END PUBLIC KEY-----" )    

        certFile.write( "\n-----BEGIN CERTIFICATE-----" )    
        for i in range( len( encodedCertificate ) ):
            if i % 64 == 0:
                certFile.write( "\n" )
            certFile.write( encodedCertificate[ i ] )
        certFile.write( "\n-----END CERTIFICATE-----\n" )    
        certFile.close()



##########################################################################
#------------------------------- Tests -----------------------------------
##########################################################################
SEALED_MASTER_KEYS_FILE_PATH   = "../sealed_master_keys.bin"
SEALED_ALLOWED_USERS_FILE_PATH = "../sealed_allowed_users.bin"

LOCAL_HOST  = "127.0.0.1"
SSM_IP      = LOCAL_HOST
# SSM_IP      = "141.212.112.151"

class TestRemoteSSMManager(unittest.TestCase):
    def setUp(self):
        self.SSM_IP = SSM_IP
        print('In setUp()')
        if self.SSM_IP == LOCAL_HOST:
            self.RunSSMApplication()
        self.StartRemoteSSM()
        
    def tearDown(self):
        print('In tearDown()')
        # time.sleep(50)
        self.remoteSSMManager.DisconnectFromSSM()
        if self.SSM_IP == LOCAL_HOST:
            self.KillSSMApplication()
        self.DeleteSealedConfigurationFiles()

    def DeleteSealedConfigurationFiles( self ):
        if os.path.exists( SEALED_MASTER_KEYS_FILE_PATH ):
            os.remove( SEALED_MASTER_KEYS_FILE_PATH )

        if os.path.exists( SEALED_ALLOWED_USERS_FILE_PATH ):
            os.remove( SEALED_ALLOWED_USERS_FILE_PATH )

    def StartRemoteSSM( self ):
        self.remoteSSMManager = RemoteSSMManager()
        try:
            time.sleep(0.1)
            self.remoteSSMManager.ConnectToSSM( self.SSM_IP )
        except Exception as e:
            print( "ERROR: ConnectToSSM failed - killing application" )
            self.KillSSMApplication()
            raise e

    def test_getVersion( self ):
        ( serverVersion, enclaveVersion ) = self.remoteSSMManager.GetVersion()

        EXPECTER_SERVER_VERSION  = b"0.0.1\x00"
        EXPECTER_ENCLAVE_VERSION = b"0.0.1\x00"

        self.assertTrue( serverVersion.startswith( EXPECTER_SERVER_VERSION ), msg="%s != %s" % ( serverVersion, EXPECTER_SERVER_VERSION ) )
        self.assertTrue( enclaveVersion.startswith( EXPECTER_SERVER_VERSION ), msg="%s != %s" % ( enclaveVersion, EXPECTER_ENCLAVE_VERSION ) )

    def test_remoteAttestationGetMsg1( self ):
        msg1 = self.remoteSSMManager.RemoteAttestation_GetMsg1()

        expectedGroupID = 0xaca
        self.assertTrue( msg1[ 'group-ID' ] == expectedGroupID,  msg="0x%x != 0x%x" % ( msg1[ 'group-ID' ], expectedGroupID ) )

        # print( "Enclave public key: " )
        # for i, byte in enumerate( msg1[ 'enclave-public-key' ] ):
        #     sys.stdout.write( "0x%2X, " % byte )
        #     if ( i + 1 ) % 8 == 0:
        #         print( "" )

    def test_remoteAttestationProcess( self ):
        msg1 = self.remoteSSMManager.RemoteAttestation_GetMsg1()

        expectedGroupID = 0xaca
        self.assertTrue( msg1[ 'group-ID' ] == expectedGroupID,  msg="0x%x != 0x%x" % ( msg1[ 'group-ID' ], expectedGroupID ) )

        self.remoteSSMManager.GenerateKeyPair                   ()
        self.remoteSSMManager.RemoteAttestation_ProcessMsg1   ( msg1 )
        msg3 = self.remoteSSMManager.RemoteAttestation_GetMsg3()
        self.remoteSSMManager.RemoteAttestation_ProcessMsg3   ( msg3 )

        # make sure exception is thrown if MAC doesn't match
        modifiedMAC = bytearray( msg3[ 'MAC' ] )
        modifiedMAC[ 5 ] ^= 1;
        msg3[ 'MAC' ] = modifiedMAC

        exceptionCaught = False
        try:
            self.remoteSSMManager.RemoteAttestation_ProcessMsg3( msg3 )
        except RemoteSSMManagerError as e:
            exceptionCaught = True

        self.assertTrue( exceptionCaught )

        self.remoteSSMManager.VerifyQuoteWithIntelAttestationServer( msg3 ) #should not throw 
        modifiedQuote           = bytearray( msg3[ 'Quote-Raw' ] )
        modifiedQuote[ 200 ] ^= 1
        msg3[ 'Quote-Raw' ]   = modifiedQuote
        
        exceptionCaught = False
        try:
            self.remoteSSMManager.VerifyQuoteWithIntelAttestationServer( msg3 )
        except IntelAttestationServerError as e:
            exceptionCaught = True

        self.assertTrue( exceptionCaught )

    def test_EstablishSession( self ):
        self.remoteSSMManager.InitSSM()
        self.remoteSSMManager.EstablishSessionKeys()

        # print( "key_session: " )
        # for i, byte in enumerate( self.remoteSSMManager.key_session ):
        #     sys.stdout.write( "0x%2X, " % byte )
        #     if ( i + 1 ) % 8 == 0:
        #         print( "" )

        self.remoteSSMManager.PingSSM()

    def test_EstablishInsecureSession( self ):    
        self.remoteSSMManager.InitSSM( performRemoteAttestation = False )
        self.remoteSSMManager.EstablishInsecureSession()
        self.remoteSSMManager.PingSSM()

    def test_EstablishSession_afterRestart( self ):
        self.remoteSSMManager.InitSSM()
        self.remoteSSMManager.EstablishSessionKeys()
        self.remoteSSMManager.PingSSM()        
        
        self.remoteSSMManager.SaveMasterKeys()
        self.remoteSSMManager.DisconnectFromSSM()

        self.KillSSMApplication()
        self.RunSSMApplication()
        self.StartRemoteSSM()

        self.remoteSSMManager.LoadMasterKeys()
        self.remoteSSMManager.EstablishSessionKeys()        
        self.remoteSSMManager.PingSSM()
    
    def test_GenerateRSAKeypair( self ):
        RSA_F4    = 0x10001
        self.remoteSSMManager.InitSSM()
        self.remoteSSMManager.EstablishSessionKeys()

        keySizeInBits     = 2048
        publicExponent     = RSA_F4
        key = self.remoteSSMManager.GenerateRSAKeyPair( keySizeInBits, publicExponent )
        self.remoteSSMManager.CreateCertificateFile( key, "testcert.cer" )

    def test_UsingGeneratedRSAKeyPair( self ):
        RSA_F4    = 0x10001
        self.remoteSSMManager.InitSSM()
        self.remoteSSMManager.EstablishSessionKeys()

        keySizeInBits     = 2048
        publicExponent     = RSA_F4
        key = self.remoteSSMManager.GenerateRSAKeyPair( keySizeInBits, publicExponent )

        dataToSign = os.urandom( 1000 )
        signature  = self.remoteSSMManager.SignRSA( dataToSign, key[ 'handle' ] ) 
    
        self.remoteSSMManager.VerifyRSASignature( dataToSign, signature, key[ 'publicKeyAsDER' ] )
        # self.remoteSSMManager.libreSSL.VerifyRSASignature( dataToSign, signature, key[ 'publicKeyAsDER' ] )

    def test_UsingGeneratedECDSAKeyPairOpenSSL( self ):
        self.remoteSSMManager.InitSSM()
        self.remoteSSMManager.EstablishSessionKeys()

        for keyType in ECC_CURVES.values():
            key = self.remoteSSMManager.GenerateECDSASAKeypair_OpenSSL( keyType )

            dataToSign = os.urandom( 1000 )
            signature  = self.remoteSSMManager.SignECDSAOpenSSL( dataToSign, key[ 'handle' ] ) 
        
            self.remoteSSMManager.VerifyECDSA_OpenSSL_Signature( dataToSign, signature, key[ 'publicKeyAsDER' ] )
        


    def test_importRSAKey( self ):
        privateKeyAsDER = base64.b64decode( self.TEST_PRIVATE_KEY )
        evpKey             = self.remoteSSMManager.libreSSL.ParsePrivateKeyAsDER( privateKeyAsDER )        
        publicKeyAsDER     = self.remoteSSMManager.libreSSL.ExtractRSAPublicKey( evpKey )

        # dataToSign = os.urandom( 1000 )
        # signature = self.remoteSSMManager.libreSSL.SignRSA( evpKey, dataToSign )
        # self.remoteSSMManager.VerifyRSASignature( dataToSign, signature, publicKeyAsDER )

        ssmUser2 = RemoteSSMManager()
        ssmUser2.GenerateKeyPair()
        
        self.remoteSSMManager.InitSSM()
        self.remoteSSMManager.EstablishSessionKeys()
        expectedIdentityToken = self.remoteSSMManager.AllowUserRegistration( ssmUser2.publicKey )

        keyHandle         = self.remoteSSMManager.ImportRSAKey( privateKeyAsDER )
        expectedHandle     = self.remoteSSMManager.cryptoWrapper.SHA256( publicKeyAsDER )[ 0:SIZE_OF_UINT64_T ]
        expectedHandle  = struct.unpack( "Q", expectedHandle )[ 0 ]
        self.assertEqual( keyHandle, expectedHandle, "keyHandle = 0x%016x, instead of expected 0x%016x" % ( keyHandle, expectedHandle ) )

        self.remoteSSMManager.DisconnectFromSSM()

        ssmUser2.ConnectToSSM( self.SSM_IP )
        ssmUser2.PerformRemoteAttestationHandshake()
        ssmUser2.EstablishSessionKeys()
        ssmUser2.PingSSM()

        dataToSign = os.urandom( 1000 )
        signature  = ssmUser2.SignRSA( dataToSign, keyHandle ) 
        ssmUser2.VerifyRSASignature( dataToSign, signature, publicKeyAsDER )

    def test_GenerateECDSASAKeypair( self ):
        self.remoteSSMManager.InitSSM()
        self.remoteSSMManager.EstablishSessionKeys()

        key = self.remoteSSMManager.GenerateECDSAKeyPair()

    def test_GenerateECDSASAKeypair_OpenSSL( self ):
        self.remoteSSMManager.InitSSM()
        self.remoteSSMManager.EstablishSessionKeys()

        for keyType in ECC_CURVES.values():
            key = self.remoteSSMManager.GenerateECDSASAKeypair_OpenSSL( keyType )
               

    def test_GenerateECDSASAKeypair_withPassword( self ):
        self.remoteSSMManager.InitSSM()
        self.remoteSSMManager.EstablishSessionKeys()

        password = bytearray( b'0'*16 )

        ssmChallenge = self.remoteSSMManager.GetChallenge()
        key = self.remoteSSMManager.GenerateECDSAKeyPair( ssmChallenge, password )

        #Using key in the regular way should fail, key is not supposed to be inn memory
        dataToSign      = os.urandom( 1000 )

        exceptionCaught = False
        try:
            signature  = self.remoteSSMManager.SignECDSA( dataToSign, key[ 'handle' ] ) 
        except RemoteSSMManagerError as err:
            self.assertTrue( err.errCode == OPENSSM_SECURE_MSG_BAD_HANDLE )
            exceptionCaught = True

        self.assertTrue( exceptionCaught )
        
        #Arm key, then use it
        ssmChallenge = self.remoteSSMManager.GetChallenge()
        self.remoteSSMManager.ArmKey( key[ 'handle' ], ssmChallenge, password )
        signature  = self.remoteSSMManager.SignECDSA( dataToSign, key[ 'handle' ] ) 
        self.remoteSSMManager.VerifyECDSASignature( dataToSign, signature, key[ 'publicKey' ] )
        
        # Should fail, arming should work only for one use
        exceptionCaught = False
        try:
            signature  = self.remoteSSMManager.SignECDSA( dataToSign, key[ 'handle' ] ) 
        except RemoteSSMManagerError as err:
            self.assertTrue( err.errCode == OPENSSM_SECURE_MSG_BAD_HANDLE )
            exceptionCaught = True

        self.assertTrue( exceptionCaught )


        #Arm Key with wrong password, should fail
        password[ 10 ] ^= 1
        exceptionCaught = False
        ssmChallenge    = self.remoteSSMManager.GetChallenge()
        try:
            self.remoteSSMManager.ArmKey( key[ 'handle' ], ssmChallenge, password )
        except RemoteSSMManagerError as err:
            self.assertTrue( err.errCode == OPENSSM_SECURE_MSG_MAC_MISMATCH )
            exceptionCaught = True

        self.assertTrue( exceptionCaught )

    def test_UsingGeneratedECDSAKeyPair( self ):
        self.remoteSSMManager.InitSSM()
        self.remoteSSMManager.EstablishSessionKeys()

        key = self.remoteSSMManager.GenerateECDSAKeyPair()

        dataToSign = os.urandom( 1000 )
        signature  = self.remoteSSMManager.SignECDSA( dataToSign, key[ 'handle' ] ) 
    
        self.remoteSSMManager.VerifyECDSASignature( dataToSign, signature, key[ 'publicKey' ] )

        #Test soundness
        signature[ 10 ] ^= 1
        exceptionCaught = False
        try:
            self.remoteSSMManager.VerifyECDSASignature( dataToSign, signature, key[ 'publicKey' ] )            
        except:
            exceptionCaught = True
            
        self.assertTrue( exceptionCaught )

    def test_Generate_AES_GCM_128_key( self ):
        self.remoteSSMManager.InitSSM()
        self.remoteSSMManager.EstablishSessionKeys()

        for keySize in AES_KEY_SIZES: 
            key = self.remoteSSMManager.Generate_AES_GCM_Key( keySize )

    def test_Using_AES_CMAC( self ):
        self.remoteSSMManager.InitSSM()
        self.remoteSSMManager.EstablishSessionKeys()

        key = self.remoteSSMManager.Generate_AES_GCM_Key( AES_CMAC_KEY = True )

        dataToMac  = os.urandom( 1000 )
        cmac1   = self.remoteSSMManager.AES_CMAC( dataToMac, key[ 'handle' ] )
        cmac2   = self.remoteSSMManager.AES_CMAC( dataToMac, key[ 'handle' ] )
        
        # print( "cmac1 = %s" % cmac1 )
        # print( "cmac2 = %s" % cmac2 )

    def test_Using_AES_GCM_128_key( self ):
        OPENSSM_SECURE_MSG_MAC_MISMATCH = 0x10D

        self.remoteSSMManager.InitSSM()
        self.remoteSSMManager.EstablishSessionKeys()

        for keySize in AES_KEY_SIZES: 
            key = self.remoteSSMManager.Generate_AES_GCM_Key( keySize )

            dataToEncrypt  = os.urandom( 1000 )
            aesGcmCipher   = self.remoteSSMManager.EncryptAES_GCM( dataToEncrypt, key[ 'handle' ] )
            decryptedData  = self.remoteSSMManager.DecryptAES_GCM( aesGcmCipher, key[ 'handle' ] )

            self.remoteSSMManager.VerifyBuffersEqual( dataToEncrypt, decryptedData )
        
            #Test MAC failure
            aesGcmCipher[ 'MAC' ][ 10 ] ^= 1
            exceptionCaught = False
            try:
                decryptedData  = self.remoteSSMManager.DecryptAES_GCM( aesGcmCipher, key[ 'handle' ] )
            except RemoteSSMManagerError as err:
                self.assertTrue( err.errCode == OPENSSM_SECURE_MSG_MAC_MISMATCH )
                exceptionCaught = True

            self.assertTrue( exceptionCaught )
            
            #Back to nnormal. No exception should be thrown:
            aesGcmCipher[ 'MAC' ][ 10 ] ^= 1
            decryptedData  = self.remoteSSMManager.DecryptAES_GCM( aesGcmCipher, key[ 'handle' ] )

            #Test bad IV
            aesGcmCipher[ 'IV' ][ 10 ] ^= 1
            exceptionCaught = False
            try:
                decryptedData  = self.remoteSSMManager.DecryptAES_GCM( aesGcmCipher, key[ 'handle' ] )
            except RemoteSSMManagerError as err:
                self.assertTrue( err.errCode == OPENSSM_SECURE_MSG_MAC_MISMATCH )
                exceptionCaught = True

            self.assertTrue( exceptionCaught )

            #Back to nnormal. No exception should be thrown:
            aesGcmCipher[ 'IV' ][ 10 ] ^= 1
            decryptedData  = self.remoteSSMManager.DecryptAES_GCM( aesGcmCipher, key[ 'handle' ] )

            #Test bad cipher
            aesGcmCipher[ 'ciphertext' ][ 10 ] ^= 1
            exceptionCaught = False
            try:
                decryptedData  = self.remoteSSMManager.DecryptAES_GCM( aesGcmCipher, key[ 'handle' ] )
            except RemoteSSMManagerError as err:
                self.assertTrue( err.errCode == OPENSSM_SECURE_MSG_MAC_MISMATCH )
                exceptionCaught = True

            self.assertTrue( exceptionCaught )

    def test_RegisterNewUser( self ):
        ssmUser2 = RemoteSSMManager()
        ssmUser2.GenerateKeyPair()
        
        self.remoteSSMManager.InitSSM()
        self.remoteSSMManager.EstablishSessionKeys()
        expectedIdentityToken = self.remoteSSMManager.AllowUserRegistration( ssmUser2.publicKey )
        self.remoteSSMManager.DisconnectFromSSM()    

    
        ssmUser2.ConnectToSSM( self.SSM_IP )
        ssmUser2.PerformRemoteAttestationHandshake()
        ssmUser2.EstablishSessionKeys()
        ssmUser2.PingSSM()
        ssmProofOfIdentity = ssmUser2.GetSSMProofOfIDentity()
        ssmUser2.DisconnectFromSSM()

        self.remoteSSMManager.VerifyBuffersEqual( ssmProofOfIdentity, expectedIdentityToken)

    def test_RegisterNewUser_useOfUnAuthorizedService( self ):
        allowedServices  = [ False ] * len( ALLOW_ALL_SERVICES )
        allowedServices[ SecureMsgType.PING ]                       = True
        allowedServices[ SecureMsgType.PROVE_SSM_IDENTITY_REQUEST ] = True


        ssmUser2 = RemoteSSMManager()
        ssmUser2.GenerateKeyPair()
        
        self.remoteSSMManager.InitSSM()
        self.remoteSSMManager.EstablishSessionKeys()
        expectedIdentityToken = self.remoteSSMManager.AllowUserRegistration( ssmUser2.publicKey, allowedServices )
        self.remoteSSMManager.DisconnectFromSSM()    

    
        ssmUser2.ConnectToSSM( self.SSM_IP )
        ssmUser2.PerformRemoteAttestationHandshake()
        ssmUser2.EstablishSessionKeys()
        ssmUser2.PingSSM()
        ssmProofOfIdentity = ssmUser2.GetSSMProofOfIDentity()

        #The following should fail!        
        RSA_F4    = 0x10001
        keySizeInBits     = 2048
        publicExponent     = RSA_F4
        
        try:
            exceptionCaught = False
            key = ssmUser2.GenerateRSAKeyPair( keySizeInBits, publicExponent )
        except:
            exceptionCaught = True

        ssmUser2.DisconnectFromSSM()

        # self.remoteSSMManager.VerifyBuffersEqual( ssmProofOfIdentity, expectedIdentityToken)
        self.assertTrue( exceptionCaught )

    def test_RegisterNewUser_useOfUnAuthorizedService_afterRestart( self ):
        allowedServices  = [ False ] * len( ALLOW_ALL_SERVICES )
        allowedServices[ SecureMsgType.PING ]                       = True
        allowedServices[ SecureMsgType.PROVE_SSM_IDENTITY_REQUEST ] = True


        ssmUser2 = RemoteSSMManager()
        ssmUser2.GenerateKeyPair()
        
        self.remoteSSMManager.InitSSM()
        self.remoteSSMManager.EstablishSessionKeys()
        expectedIdentityToken = self.remoteSSMManager.AllowUserRegistration( ssmUser2.publicKey, allowedServices )
        self.remoteSSMManager.DisconnectFromSSM()    

    
        ssmUser2.ConnectToSSM( self.SSM_IP )
        ssmUser2.PerformRemoteAttestationHandshake()
        ssmUser2.EstablishSessionKeys()
        ssmUser2.PingSSM()
        ssmProofOfIdentity = ssmUser2.GetSSMProofOfIDentity()

        #Restart
        self.KillSSMApplication()
        self.RunSSMApplication()
        time.sleep(0.1)

        #reconnect
        ssmUser2.ConnectToSSM( self.SSM_IP )
        ssmUser2.EstablishSessionKeys()

        #The following should fail!        
        RSA_F4    = 0x10001
        keySizeInBits     = 2048
        publicExponent     = RSA_F4
        
        try:
            exceptionCaught = False
            key = ssmUser2.GenerateRSAKeyPair( keySizeInBits, publicExponent )
        except:
            exceptionCaught = True

        ssmUser2.DisconnectFromSSM()

        # self.remoteSSMManager.VerifyBuffersEqual( ssmProofOfIdentity, expectedIdentityToken)
        self.assertTrue( exceptionCaught )


    def test_RegisterNewUser_badPublicKey( self ):
        ssmUser2 = RemoteSSMManager()
        ssmUser2.GenerateKeyPair()
        
        user2PublicKey = bytearray( ssmUser2.publicKey )
        user2PublicKey[ 10 ] ^= 1 

        self.remoteSSMManager.InitSSM()
        self.remoteSSMManager.EstablishSessionKeys()
        self.remoteSSMManager.AllowUserRegistration( user2PublicKey )
        self.remoteSSMManager.DisconnectFromSSM()    

        exceptionCaught = False
        try:
            ssmUser2.ConnectToSSM( self.SSM_IP )
            try:
                ssmUser2.PerformRemoteAttestationHandshake()    
                ssmUser2.EstablishSessionKeys()
            except:
                exceptionCaught = True
        finally:
            ssmUser2.DisconnectFromSSM()

        self.assertTrue( exceptionCaught )

    def test_GetConfigID_RegisterNewUser_loginAfterRestart( self ):
        ssmUser2 = RemoteSSMManager()
        ssmUser2.GenerateKeyPair()
        
        self.remoteSSMManager.InitSSM()
        self.remoteSSMManager.EstablishSessionKeys()
        configID_afterInit = self.remoteSSMManager.GetConfigurationID()

        # print( "configID_afterInit = %s" % configID_afterInit )
        self.remoteSSMManager.AllowUserRegistration( ssmUser2.publicKey )
        configID_afterAlowingUser = self.remoteSSMManager.GetConfigurationID()
        # print( "configID_afterAlowingUser = %s" % configID_afterAlowingUser )
        self.remoteSSMManager.DisconnectFromSSM()    

        #REgister user2
        ssmUser2.ConnectToSSM( self.SSM_IP )
        ssmUser2.PerformRemoteAttestationHandshake()
        ssmUser2.EstablishSessionKeys()
        configID_secondUserConnected = ssmUser2.GetConfigurationID()
        # print( "configID_secondUserConnected = %s" % configID_secondUserConnected )
        self.remoteSSMManager.VerifyBuffersEqual( configID_secondUserConnected, configID_afterAlowingUser )
        ssmUser2.PingSSM()
        ssmUser2.DisconnectFromSSM()

        #Restart
        self.KillSSMApplication()
        self.RunSSMApplication()
        time.sleep(0.1)

        #Login user2
        self.remoteSSMManager.ConnectToSSM( self.SSM_IP )
        self.remoteSSMManager.EstablishSessionKeys()
        configID_secondUserConnected_afterRestart = self.remoteSSMManager.GetConfigurationID()
        # print( "configID_adminConnected_afterRestart = %s" % configID_secondUserConnected_afterRestart )
        self.remoteSSMManager.VerifyBuffersEqual( configID_secondUserConnected_afterRestart, configID_afterAlowingUser )
        self.remoteSSMManager.PingSSM()
        self.remoteSSMManager.DisconnectFromSSM()


    def test_RegisterNewUser_loginAfterRestart( self ):
        ssmUser2 = RemoteSSMManager()
        ssmUser2.GenerateKeyPair()
        
        self.remoteSSMManager.InitSSM()
        self.remoteSSMManager.EstablishSessionKeys()
        self.remoteSSMManager.AllowUserRegistration( ssmUser2.publicKey )
        self.remoteSSMManager.DisconnectFromSSM()    

        #REgister user2
        ssmUser2.ConnectToSSM( self.SSM_IP )
        ssmUser2.PerformRemoteAttestationHandshake()
        ssmUser2.EstablishSessionKeys()
        ssmUser2.PingSSM()
        ssmUser2.DisconnectFromSSM()

        #Restart
        self.KillSSMApplication()
        self.RunSSMApplication()
        time.sleep(0.1)

        #Login user2
        ssmUser2.ConnectToSSM( self.SSM_IP )
        ssmUser2.EstablishSessionKeys()
        ssmUser2.PingSSM()
        ssmUser2.DisconnectFromSSM()

    def test_RegisterNewUser_loginOfSecurityOfficerAfterRestart( self ):
        ssmUser2 = RemoteSSMManager()
        ssmUser2.GenerateKeyPair()
        
        self.remoteSSMManager.InitSSM()
        self.remoteSSMManager.EstablishSessionKeys()
        self.remoteSSMManager.AllowUserRegistration( ssmUser2.publicKey )
        self.remoteSSMManager.DisconnectFromSSM()    

        #REgister user2
        ssmUser2.ConnectToSSM( self.SSM_IP )
        ssmUser2.PerformRemoteAttestationHandshake()
        ssmUser2.EstablishSessionKeys()
        ssmUser2.PingSSM()
        ssmUser2.DisconnectFromSSM()

        #Restart
        self.KillSSMApplication()
        self.RunSSMApplication()
        time.sleep(0.1)

        #Login of security officer
        self.remoteSSMManager.ConnectToSSM( self.SSM_IP )
        self.remoteSSMManager.EstablishSessionKeys()
        self.remoteSSMManager.PingSSM()
        self.remoteSSMManager.DisconnectFromSSM()

    def test_RegisterNewUser_loginOfSecurityNoRestart( self ):
        ssmUser2 = RemoteSSMManager()
        ssmUser2.GenerateKeyPair()
        
        self.remoteSSMManager.InitSSM()
        self.remoteSSMManager.EstablishSessionKeys()
        self.remoteSSMManager.AllowUserRegistration( ssmUser2.publicKey )
        self.remoteSSMManager.DisconnectFromSSM()    

        #Register user2
        ssmUser2.ConnectToSSM( self.SSM_IP )
        ssmUser2.PerformRemoteAttestationHandshake()
        ssmUser2.EstablishSessionKeys()
        ssmUser2.PingSSM()
        ssmUser2.DisconnectFromSSM()

        #Login of security officer
        self.remoteSSMManager.ConnectToSSM( self.SSM_IP )
        self.remoteSSMManager.EstablishSessionKeys()
        self.remoteSSMManager.PingSSM()
        self.remoteSSMManager.DisconnectFromSSM()

    
    def test_GenerateECDSASAKeypair_mutualCustody( self ):
        ssmUser2_smartCard = RemoteSSMManager()
        ssmUser2_smartCard.GenerateKeyPair()

        ssmUser3 = RemoteSSMManager()
        ssmUser3.GenerateKeyPair()
        
        self.InitSSMAndAllowUsers( [ ssmUser2_smartCard.publicKey, ssmUser3.publicKey ] )

        self.RegisterUser( ssmUser2_smartCard )
        self.RegisterUser( ssmUser3 )

        #Register user3
        ssmUser3.ConnectToSSM( self.SSM_IP )
        ssmUser3.EstablishSessionKeys()
        
        # #Create key with mutual custody:
        # #Step 1 - create protection token by smart card:
        ssmChallenge = ssmUser3.GetChallenge()
        creationToken, tokenID = ssmUser2_smartCard.CreateProtectionTokenForKeyGeneration( ssmChallenge )
        password     = os.urandom( SIZE_OF_PROTECTION_SECRET )
        key         = ssmUser3.GenerateECDSAKeyPair( ssmChallenge, password, [ creationToken ] )

        #Sign and verify:
        ssmChallenge     = ssmUser3.GetChallenge()
        usageToken         = ssmUser2_smartCard.AllowKeyUsage( ssmChallenge, tokenID )
        dataToSign         = os.urandom( 1000 )
        ssmUser3.ArmKey( key[ 'handle' ], ssmChallenge, password, [ usageToken ] )
        signature          = ssmUser3.SignECDSA( dataToSign, key[ 'handle' ] ) 
        ssmUser3.VerifyECDSASignature( dataToSign, signature, key[ 'publicKey' ] )

        #Edge case 1 - Arming only with password, not with token
        ssmChallenge     = ssmUser3.GetChallenge()
        exceptionCaught = False
        try:
            ssmUser3.ArmKey( key[ 'handle' ], ssmChallenge, password ) #missing token
        except RemoteSSMManagerError as err:
            self.assertTrue( err.errCode == OPENSSM_SECURE_MSG_MAC_MISMATCH )
            exceptionCaught = True

        self.assertTrue( exceptionCaught )

        # #Edge case 2 - Arming only with password, and bad token
        ssmChallenge         = ssmUser3.GetChallenge()
        usageToken             = ssmUser2_smartCard.AllowKeyUsage( ssmChallenge, tokenID )
        usageToken          = usageToken[:] #copy by value
        usageToken[ 60 ]   ^= 1 #corrupt token

        exceptionCaught     = False
        try:
            ssmUser3.ArmKey( key[ 'handle' ], ssmChallenge, password, [ usageToken ] ) 
        except RemoteSSMManagerError as err:
            self.assertTrue( err.errCode == OPENSSM_SECURE_MSG_SHARED_CUSTUDY_ERROR )
            exceptionCaught = True

        self.assertTrue( exceptionCaught )

        # #Edge case 3 - replaying token should fail
        ssmChallenge         = ssmUser3.GetChallenge()
        usageToken             = ssmUser2_smartCard.AllowKeyUsage( ssmChallenge, tokenID )
        ssmUser3.ArmKey( key[ 'handle' ], ssmChallenge, password, [ usageToken ] ) 
        signature  = ssmUser3.SignECDSA( dataToSign, key[ 'handle' ] ) 
        ssmUser3.VerifyECDSASignature( dataToSign, signature, key[ 'publicKey' ] )

        exceptionCaught     = False
        try:
            ssmUser3.ArmKey( key[ 'handle' ], ssmChallenge, password, [ usageToken ] ) 
        except RemoteSSMManagerError as err:
            self.assertTrue( err.errCode == OPENSSM_SECURE_MSG_SHARED_CUSTUDY_ERROR )
            exceptionCaught = True

        self.assertTrue( exceptionCaught )

    def test_SyncSession( self ):
        self.remoteSSMManager.InitSSM()
        self.remoteSSMManager.EstablishSessionKeys()
        self.remoteSSMManager.PingSSM()
        self.remoteSSMManager.sessionDecryptMsgCounter -= 1
        
        exceptionCaught = False
        try:
            self.remoteSSMManager.PingSSM()
        except:
            exceptionCaught = True
        self.assertTrue( exceptionCaught )

        self.remoteSSMManager.SyncSecureSession()
        self.remoteSSMManager.PingSSM()
        self.remoteSSMManager.PingSSM()

############################

    def test_Ping_latency( self ):
        NUM_OPERATIONS = 1000000
        PAYLOAD        = 0xdeadbeef

        self.responses = []

        self.remoteSSMManager.InitSSM()
        self.remoteSSMManager.EstablishSessionKeys()

        self.remoteSSMManager.log.setLevel(0)
        self.remoteSSMManager.cryptoWrapper.log.setLevel(0)

        startTime   = time.time()

        for i in range( NUM_OPERATIONS ):
            # self.remoteSSMManager.PingSSM()
            self.remoteSSMManager.SendPingMsg( PAYLOAD )
            msgRaw    = self.remoteSSMManager.ReadMsgFromSocket()
            self.responses.append( msgRaw )
        
 
        for i in range( len( self.responses ) ):            
            secureMsg = self.remoteSSMManager.ParseMsg( self.responses[ i ] )
        
        #And... stop the clock
        totalTime = (time.time() - startTime)
        
        # print performance:
        print( "#" * 50 + " Ping latency" )
        print( "Total time: %f, num operations: %d, num operations per second: %f, latency = %f ms" % \
            ( totalTime, NUM_OPERATIONS , NUM_OPERATIONS  / totalTime, 1000.0 * totalTime / NUM_OPERATIONS  ) )
        print( "#" * 50 )


    def test_Ping_performanceTest( self ):
        NUM_OPERATIONS = 1000000

        USE_SECURE_SESSION = True
        # USE_SECURE_SESSION = False

        if USE_SECURE_SESSION:
            self.remoteSSMManager.InitSSM()
            self.remoteSSMManager.EstablishSessionKeys()
        else:
            self.remoteSSMManager.InitSSM( performRemoteAttestation = False )
            self.remoteSSMManager.EstablishInsecureSession()

        # key = self.remoteSSMManager.Generate_AES_GCM_Key()

        # keyHandle  = key[ 'handle' ] 

        self.remoteSSMManager.log.setLevel(0)
        self.remoteSSMManager.cryptoWrapper.log.setLevel(0)

        # dataToEncrypt  = os.urandom( 1*1024 )

        self.responses = []

        # self.misreadCounter = 0

        sendRatio       = 500
        # recvRatio       = 700
        sentIdx         = 0
        recvIdx         = 0
        # earlyStart      = 1000
        recvRatio       = sendRatio
        earlyStart      = sendRatio

        PAYLOAD    = 0xdeadbeef
        startTime   = time.time()

        #Send early requests to fill queue
        for i in range( earlyStart ):
            sentMsgSize = self.remoteSSMManager.SendPingMsg( PAYLOAD )
            # self.remoteSSMManager.SendDataRequest(     dataToEncrypt, 
            #                                         keyHandle, 
            #                                         SecureMsgType.AES_GCM_ENCRYPT_REQUEST )
        sentIdx += earlyStart

        #Send and receive requests in according to sendRatio & recvRatio
        while sentIdx < NUM_OPERATIONS:
            for i in range( sendRatio ):
                sentMsgSize = self.remoteSSMManager.SendPingMsg( PAYLOAD )
                # self.remoteSSMManager.SendDataRequest(     dataToEncrypt, 
                #                                         keyHandle, 
                #                                         SecureMsgType.AES_GCM_ENCRYPT_REQUEST )
            sentIdx += sendRatio

            for i in range( recvRatio ):
                msgRaw    = self.remoteSSMManager.ReadMsgFromSocket()
                self.responses.append( msgRaw )

            recvIdx += recvRatio

        #And... stop the clock
        totalTime = (time.time() - startTime)

        #Receive remaining responses
        for i in range( sentIdx - recvIdx ):
            msgRaw    = self.remoteSSMManager.ReadMsgFromSocket()
            self.responses.append( msgRaw )
        
        


        # #Parse responses:
        print( "## len( self.responses ) = %d" % len( self.responses ) )
        
        if USE_SECURE_SESSION == False:
            for i in range( len( self.responses ) ):            
                secureMsg = self.remoteSSMManager.ParseInsecureMsg( self.responses[ i ] )
        else:
            for i in range( len( self.responses ) ):            
                secureMsg = self.remoteSSMManager.ParseMsg( self.responses[ i ] )
        
        
        # print performance:
        print( "#" * 50 )
        print( "Total time: %f, num operations: %d, num operations per second: %f" % \
            ( totalTime, len( self.responses ) , len( self.responses )  / totalTime ) )
        print( "#" * 50 )

    def test_UsingAES_GCM_performanceTest( self ):
        NUM_OPERATIONS = 1000000 / 8

        USE_SECURE_SESSION = True
        # USE_SECURE_SESSION = False

        if USE_SECURE_SESSION:
            self.remoteSSMManager.InitSSM()
            self.remoteSSMManager.EstablishSessionKeys()
        else:
            self.remoteSSMManager.InitSSM( performRemoteAttestation = False )
            self.remoteSSMManager.EstablishInsecureSession()

        key = self.remoteSSMManager.Generate_AES_GCM_Key()

        keyHandle  = key[ 'handle' ] 

        self.remoteSSMManager.log.setLevel(0)
        self.remoteSSMManager.cryptoWrapper.log.setLevel(0)

        dataToEncrypt  = os.urandom( 1*1024 )

        self.responses = []

        # self.misreadCounter = 0

        sendRatio     = 700
        recvRatio     = 700
        sentIdx     = 0
        recvIdx     = 0
        earlyStart     = 1000


        startTime = time.time()

        #Send early requests to fill queue
        for i in range( earlyStart ):
            self.remoteSSMManager.SendDataRequest(     dataToEncrypt, 
                                                    keyHandle, 
                                                    SecureMsgType.AES_GCM_ENCRYPT_REQUEST )
        sentIdx += earlyStart

        #Send and receive requests in according to sendRatio & recvRatio
        while sentIdx < NUM_OPERATIONS:
            for i in range( sendRatio ):
                self.remoteSSMManager.SendDataRequest(     dataToEncrypt, 
                                                        keyHandle, 
                                                        SecureMsgType.AES_GCM_ENCRYPT_REQUEST )
            sentIdx += sendRatio

            for i in range( recvRatio ):
                msgRaw    = self.remoteSSMManager.ReadMsgFromSocket()
                self.responses.append( msgRaw )

            recvIdx += recvRatio

        #Receive remaining responses
        for i in range( sentIdx - recvIdx ):
            msgRaw    = self.remoteSSMManager.ReadMsgFromSocket()
            self.responses.append( msgRaw )
        
        #Parse responses:
        print( "## len( self.responses ) = %d" % len( self.responses ) )
        if USE_SECURE_SESSION == False:
            for i in range( len( self.responses ) ):            
                secureMsg = self.remoteSSMManager.ParseInsecureMsg( self.responses[ i ] )
        else:
            for i in range( len( self.responses ) ):            
                secureMsg = self.remoteSSMManager.ParseMsg( self.responses[ i ] )
        
        #And... stop the clock
        totalTime = (time.time() - startTime)

        # print performance:
        print( "#" * 50 )
        print( "Total time: %f, num operations: %d, num operations per second: %f" % \
            ( totalTime, len( self.responses ) , len( self.responses )  / totalTime ) )
        print( "#" * 50 )
        # print( "self.misreadCounter = %d" % self.misreadCounter)

    # def test_UsingGeneratedECDSAKeyPair_performanceTest( self ):
    #     self.remoteSSMManager.log.setLevel(0)
    #     self.remoteSSMManager.cryptoWrapper.log.setLevel(0)


    #     USE_SECURE_SESSION = True
    #     USE_SECURE_SESSION = False

    #     if USE_SECURE_SESSION:
    #         self.remoteSSMManager.InitSSM()
    #         self.remoteSSMManager.EstablishSessionKeys()
    #     else:
    #         self.remoteSSMManager.InitSSM( performRemoteAttestation = False )
    #         self.remoteSSMManager.EstablishInsecureSession()

    #     key          = self.remoteSSMManager.GenerateECDSAKeyPair()
    #     dataToSign     = os.urandom( 1024 )
    #     keyHandle      = key[ 'handle' ] 

    #     self.responses = []

    #     # self.misreadCounter = 0
    #     NUM_OPERATIONS = 1000000
    #     sendRatio     = 700
    #     recvRatio     = 700
    #     sentIdx     = 0
    #     recvIdx     = 0
    #     earlyStart     = 1000

    #     startTime = time.time()

    #     #Send early requests to fill queue
    #     for i in range( earlyStart ):
    #         self.remoteSSMManager.SendDataRequest(     dataToSign, 
    #                                                 keyHandle, 
    #                                                 SecureMsgType.ECDSA_SIGN_REQUEST )
    #     sentIdx += earlyStart

    #     #Send and receive requests in according to sendRatio & recvRatio
    #     while sentIdx < NUM_OPERATIONS:
    #         for i in range( sendRatio ):
    #             self.remoteSSMManager.SendDataRequest(     dataToSign, 
    #                                                 keyHandle, 
    #                                                 SecureMsgType.ECDSA_SIGN_REQUEST )
    #         sentIdx += sendRatio

    #         for i in range( recvRatio ):
    #             msgRaw    = self.remoteSSMManager.ReadMsgFromSocket()
    #             self.responses.append( msgRaw )

    #         recvIdx += recvRatio

    #     #Receive remaining responses
    #     for i in range( sentIdx - recvIdx ):
    #         msgRaw    = self.remoteSSMManager.ReadMsgFromSocket()
    #         self.responses.append( msgRaw )
        
    #     #Parse responses:
    #     print( "## len( self.responses ) = %d" % len( self.responses ) )
    #     if USE_SECURE_SESSION == False:
    #         for i in range( len( self.responses ) ):            
    #             secureMsg = self.remoteSSMManager.ParseInsecureMsg( self.responses[ i ] )
    #     else:
    #         for i in range( len( self.responses ) ):            
    #             secureMsg = self.remoteSSMManager.ParseMsg( self.responses[ i ] )
        
    #     #And... stop the clock
    #     totalTime = (time.time() - startTime)

    #     # print performance:
    #     print( "#" * 50 )
    #     print( "ECDSA Total time: %f, num operations: %d, num operations per second: %f" % \
    #         ( totalTime, len( self.responses ) , len( self.responses )  / totalTime ) )
    #     print( "#" * 50 )
    #     # print( "self.misreadCounter = %d" % self.misreadCounter)
        
    def test_UsingGeneratedECDSAOpenSSLKeyPair_performanceTest( self ):
        self.remoteSSMManager.InitSSM()
        self.remoteSSMManager.EstablishSessionKeys()

        #supress log msgs:
        self.remoteSSMManager.log.setLevel(0)
        self.remoteSSMManager.cryptoWrapper.log.setLevel(0)

        # for keySizeInBits in [ 1024, 2048, 4096 ]:
        #     transactionsPerSecond[ keySizeInBits ] = self.EsitimatePErformance_RSA_Sign( keySizeInBits )
        
        keyParams = { "secp256k1" : 20000 ,
                      "secp384r1" : 10000 ,
                      "secp521r1" : 5000 }

        allExperiments = {}
        for keyType in keyParams.keys():
            key = self.remoteSSMManager.GenerateECDSASAKeypair_OpenSSL( ECC_CURVES[ keyType ] )

            allExperiments[ keyType ]   = {}
            opsPerSecond                = []
            for i in range( 10 ):
                opsPerSecond.append( self.EstimatePerformance( keyHandle       = key[ 'handle' ], 
                                                               requestType     = SecureMsgType.ECDSA_SIGN_OPENSSL_REQUEST ,
                                                               numOperations   = keyParams[ keyType ],
                                                               name            = keyType ) )
                
            pprint.pprint( allExperiments )
            allExperiments[ keyType ][ 'opsPerSecond' ] = opsPerSecond
            allExperiments[ keyType ][ 'std' ]          = statistics.stdev( opsPerSecond )
            allExperiments[ keyType ][ 'mean' ]         = statistics.mean( opsPerSecond )
            
        pprint.pprint( allExperiments )      

        for keyType in allExperiments.keys():
            print( "%20s: %10.4f ops/second" % ( keyType, allExperiments[ keyType ][ 'mean' ] ))  

        for keyType in allExperiments.keys():
            std = allExperiments[ keyType ][ 'std' ]
            mean = allExperiments[ keyType ][ 'mean' ]
            print( "%20s: %10.4f (%2.2f%%) std (%%)" % ( keyType, std , std/mean * 100 ))  

    def test_Using_AES_GCM_128_key_performance_test( self ):
        self.remoteSSMManager.InitSSM()
        self.remoteSSMManager.EstablishSessionKeys()

        #supress log msgs:
        self.remoteSSMManager.log.setLevel(0)
        self.remoteSSMManager.cryptoWrapper.log.setLevel(0)

        # for keySizeInBits in [ 1024, 2048, 4096 ]:
        #     transactionsPerSecond[ keySizeInBits ] = self.EsitimatePErformance_RSA_Sign( keySizeInBits )
        
        keyParams = { 128 : 50000 ,
                      192 : 50000 ,
                      256 : 50000 }

        allExperiments = {}
        for keyType in keyParams.keys():
            keySizeInBits = keyType
            key = self.remoteSSMManager.Generate_AES_GCM_Key( keySizeInBits )

            allExperiments[ keyType ]   = {}
            opsPerSecond                = []
            for i in range( 4 ):
                opsPerSecond.append( self.EstimatePerformance( keyHandle       = key[ 'handle' ], 
                                                               requestType     = SecureMsgType.AES_GCM_ENCRYPT_REQUEST ,
                                                               numOperations   = keyParams[ keySizeInBits ],
                                                               name            = keyType ) )
                
            pprint.pprint( allExperiments )
            allExperiments[ keyType ][ 'opsPerSecond' ] = opsPerSecond
            allExperiments[ keyType ][ 'std' ]          = statistics.stdev( opsPerSecond )
            allExperiments[ keyType ][ 'mean' ]         = statistics.mean( opsPerSecond )
            
        pprint.pprint( allExperiments )      

        for keyType in allExperiments.keys():
            print( "%20s: %10.4f ops/second" % ( keyType, allExperiments[ keyType ][ 'mean' ] ))  

        for keyType in allExperiments.keys():
            std = allExperiments[ keyType ][ 'std' ]
            mean = allExperiments[ keyType ][ 'mean' ]
            print( "%20s: %10.4f (%2.2f%%) std (%%)" % ( keyType, std , std/mean * 100 ))  
        

    def test_UsingGeneratedRSAKeyPair_performanceTest( self ):
        self.remoteSSMManager.InitSSM()
        self.remoteSSMManager.EstablishSessionKeys()

        #supress log msgs:
        self.remoteSSMManager.log.setLevel(0)
        self.remoteSSMManager.cryptoWrapper.log.setLevel(0)

        # for keySizeInBits in [ 1024, 2048, 4096 ]:
        #     transactionsPerSecond[ keySizeInBits ] = self.EsitimatePErformance_RSA_Sign( keySizeInBits )
        
        keyParams = { 2048 : 5000 ,
                      3072 : 1000 ,
                      4096 : 500  }

        allExperiments = {}
        for keyType in keyParams.keys():
            keyHandle       = self.CreateRSAKeyWithSSM( keyType )

            allExperiments[ keyType ]   = {}
            opsPerSecond                = []
            for i in range( 6 ):
                opsPerSecond.append( self.EstimatePerformance( keyHandle       = keyHandle, 
                                                               requestType     = SecureMsgType.RSA_SIGN_REQUEST ,
                                                               numOperations   = keyParams[ keyType ],
                                                               name            = keyType ) )
                
            pprint.pprint( allExperiments )
            allExperiments[ keyType ][ 'opsPerSecond' ] = opsPerSecond
            allExperiments[ keyType ][ 'std' ]          = statistics.stdev( opsPerSecond )
            allExperiments[ keyType ][ 'mean' ]         = statistics.mean( opsPerSecond )
            
        pprint.pprint( allExperiments )      

        for keyType in allExperiments.keys():
            print( "%20s: %10.4f ops/second" % ( keyType, allExperiments[ keyType ][ 'mean' ] ))  

        for keyType in allExperiments.keys():
            std = allExperiments[ keyType ][ 'std' ]
            mean = allExperiments[ keyType ][ 'mean' ]
            print( "%20s: %10.4f (%2.2f%%) std (%%)" % ( keyType, std , std/mean * 100 ))  
        # self.remoteSSMManager.InitSSM()
        # self.remoteSSMManager.EstablishSessionKeys()

        # #supress log msgs:
        # self.remoteSSMManager.log.setLevel(0)
        # self.remoteSSMManager.cryptoWrapper.log.setLevel(0)

        # # for keySizeInBits in [ 1024, 2048, 4096 ]:
        # #     transactionsPerSecond[ keySizeInBits ] = self.EsitimatePErformance_RSA_Sign( keySizeInBits )
        
        # keyParams = { 2048 : 5000 ,
        #               3072 : 1000 ,
        #               4096 : 500  }

        # allExperiments = {}
        # for keySize in keyParams.keys():
        #     allExperiments[ keySize ]   = {}
        #     opsPerSecond                = []
        #     for i in range( 10 ):
        #         opsPerSecond.append( self.EsitimatePErformance_RSA_Sign( keySize, NUM_OPERATIONS = keyParams[ keySize ] ) )
        #         # opsPerSecond.append( self.EsitimatePerformance( keySize, NUM_OPERATIONS = keyParams[ keySize ] ) )??????????/
                
        #     pprint.pprint( allExperiments )
        #     allExperiments[ keySize ][ 'opsPerSecond' ] = opsPerSecond
        #     allExperiments[ keySize ][ 'std' ]          = statistics.stdev( opsPerSecond )
        #     allExperiments[ keySize ][ 'mean' ]         = statistics.mean( opsPerSecond )
            
        # pprint.pprint( allExperiments )        
        #     # print( "std = %f" % statistics.stdev( allExperiments ) )
        #     # print( "mean = %f" % statistics.mean( allExperiments ) )
        
        
    def InitSession( self, useSecureSession = True ):
        if useSecureSession:
            self.remoteSSMManager.InitSSM()
            self.remoteSSMManager.EstablishSessionKeys()
        else:
            self.remoteSSMManager.InitSSM( performRemoteAttestation = False )
            self.remoteSSMManager.EstablishInsecureSession()

    def CreateRSAKeyWithSSM( self, keySizeInBits ):
        RSA_F4            = 0x10001
        publicExponent     = RSA_F4
        key             = self.remoteSSMManager.GenerateRSAKeyPair( keySizeInBits, publicExponent )
        keyHandle          = key[ 'handle' ] 

        return keyHandle


    def EstimatePerformance( self, keyHandle, requestType, numOperations, name ):
        self.remoteSSMManager.log.setLevel(0)
        self.remoteSSMManager.cryptoWrapper.log.setLevel(0)

        USE_SECURE_SESSION = True

        data            = os.urandom( 1024 )
        self.responses  = []

        sendRatio     = 1000
        recvRatio     = sendRatio
        sentIdx     = 0
        recvIdx     = 0
        earlyStart     = sendRatio

        startTime = time.time()

        #Send early requests to fill queue
        for i in range( earlyStart ):
            self.remoteSSMManager.SendDataRequest( data, 
                                                   keyHandle, 
                                                   requestType )
        sentIdx += earlyStart

        #Send and receive requests in according to sendRatio & recvRatio
        while sentIdx < numOperations:
            for i in range( sendRatio ):
                self.remoteSSMManager.SendDataRequest(  data, 
                                                        keyHandle, 
                                                        requestType )
            sentIdx += sendRatio

            for i in range( recvRatio ):
                msgRaw    = self.remoteSSMManager.ReadMsgFromSocket()
                self.responses.append( msgRaw )

            recvIdx += recvRatio

        #Receive remaining responses
        for i in range( sentIdx - recvIdx ):
            msgRaw    = self.remoteSSMManager.ReadMsgFromSocket()
            self.responses.append( msgRaw )
        
        #Parse responses:
        print( "## len( self.responses ) = %d" % len( self.responses ) )
        if USE_SECURE_SESSION == False:
            for i in range( len( self.responses ) ):            
                secureMsg = self.remoteSSMManager.ParseInsecureMsg( self.responses[ i ] )
        else:
            for i in range( len( self.responses ) ):            
                secureMsg = self.remoteSSMManager.ParseMsg( self.responses[ i ] )
        
        #And... stop the clock
        totalTime = (time.time() - startTime)

        # print performance:
        print( "#" * 50 )
        print( "%s Total time: %f, num operations: %d, num operations per second: %f" % \
            ( name, totalTime, len( self.responses ) , len( self.responses )  / totalTime ) )
        print( "#" * 50 )

        throughput = len( self.responses )  / totalTime 
        
        return throughput

        self.remoteSSMManager.log.setLevel(0)
        self.remoteSSMManager.cryptoWrapper.log.setLevel(0)

        USE_SECURE_SESSION = True
        # USE_SECURE_SESSION = False
        # self.InitSession( USE_SECURE_SESSION )

        keyHandle       = self.CreateRSAKeyWithSSM( keySizeInBits )
        dataToSign         = os.urandom( 1024 )
        self.responses     = []

        # self.misreadCounter = 0
        # NUM_OPERATIONS = 5 * 10000 / 1

        sendRatio     = 20
        recvRatio     = sendRatio
        sentIdx     = 0
        recvIdx     = 0
        earlyStart     = sendRatio

        startTime = time.time()

        #Send early requests to fill queue
        for i in range( earlyStart ):
            self.remoteSSMManager.SendDataRequest(     dataToSign, 
                                                        keyHandle, 
                                                        SecureMsgType.RSA_SIGN_REQUEST )
        sentIdx += earlyStart

        #Send and receive requests in according to sendRatio & recvRatio
        while sentIdx < NUM_OPERATIONS:
            for i in range( sendRatio ):
                self.remoteSSMManager.SendDataRequest(     dataToSign, 
                                                        keyHandle, 
                                                        SecureMsgType.RSA_SIGN_REQUEST )
            sentIdx += sendRatio

            for i in range( recvRatio ):
                msgRaw    = self.remoteSSMManager.ReadMsgFromSocket()
                self.responses.append( msgRaw )

            recvIdx += recvRatio

        #Receive remaining responses
        for i in range( sentIdx - recvIdx ):
            msgRaw    = self.remoteSSMManager.ReadMsgFromSocket()
            self.responses.append( msgRaw )
        
        #Parse responses:
        print( "## len( self.responses ) = %d" % len( self.responses ) )
        if USE_SECURE_SESSION == False:
            for i in range( len( self.responses ) ):            
                secureMsg = self.remoteSSMManager.ParseInsecureMsg( self.responses[ i ] )
        else:
            for i in range( len( self.responses ) ):            
                secureMsg = self.remoteSSMManager.ParseMsg( self.responses[ i ] )
        
        #And... stop the clock
        totalTime = (time.time() - startTime)

        # print performance:
        print( "#" * 50 )
        print( "RSA %d bits Total time: %f, num operations: %d, num operations per second: %f" % \
            ( keySizeInBits, totalTime, len( self.responses ) , len( self.responses )  / totalTime ) )
        print( "#" * 50 )

        throughput = len( self.responses )  / totalTime 
        
        return throughput


    def InitSSMAndAllowUsers( self, userIDsToAllow ):
        self.remoteSSMManager.InitSSM()
        self.remoteSSMManager.EstablishSessionKeys()

        for userID in userIDsToAllow:
            self.remoteSSMManager.AllowUserRegistration( userID )

        self.remoteSSMManager.DisconnectFromSSM()    

    def RegisterUser( self, ssmUser ):
        ssmUser.ConnectToSSM( self.SSM_IP )
        ssmUser.PerformRemoteAttestationHandshake()
        ssmUser.EstablishSessionKeys()
        ssmUser.PingSSM()
        ssmUser.DisconnectFromSSM()

    def RunSSMApplication( self ):
        WORKING_DIRECTORY     = ".."
        APP_CMD_LINE         = ["gdb", "-ex", "run", "./app"]
        APP_CMD_LINE         = ["./app"]
        # APP_CMD_LINE         = ["/opt/intel/sgxsdk/bin/sgx-gdb", "-ex", "run", "./app"]
        self.serverProcess = subprocess.Popen( APP_CMD_LINE, cwd = WORKING_DIRECTORY )
        time.sleep(0.3)

    def KillSSMApplication( self ):
        print( "KillSSMApplication" )
        KILL_SIGNAL = 9
        self.serverProcess.send_signal( KILL_SIGNAL )

    TEST_PRIVATE_KEY = """  
    MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC8EVfalgsiR1M0
    fb0kIZNeLEJLGYxXHJiVDm17QY6vSqoIXJD3rDS+RqAcoG+xP9XocMqm5gsj7iNZ
    JJBZ7QVfWBdwvTZm3mUylmq/BWL6+2JVQ1kAafWjcoZd4SeIxjrLrnVMVAMptvAj
    EkTdi7rekWTBSuCy935TzDLkqiaEji++gWy/l251nm8nFJxdalqwcEVnjlgyLCuH
    ahwtbE1Zp16lEJ+9Qr3S2bFwdzRoBfLrYog+qro4SInMkdgrSNp16bAOHCwmWEik
    bM8biIgBHzoqCGMHa9OTj7okDVAJ++HSiM2Op/OIbKV0QGW8hOoB1GZ2d2xjGW5H
    o5N6VA/pAgMBAAECggEBAKWyLhJTMhoQd1l/Ev7baiiFnB7osoIpmrFxFbqLxvfg
    M7DMRZlBKvMd7IFsRRwInyF9Br9HXTdZ3+DxWxEvyBT52yUkP+MgPE72wbPtPgjd
    JQT0Il0//gD0rTfXYOqbpD/CRGxsdKDzId30gaIkMw9XUEsQ+qoTbkTMW2amFuuf
    iYsgtccsZzqu1vZpfb2TGkrg6DF0d5FaWCFJLnlargFfr8YN+B14Ns2WnyUHnhGI
    9QEDszJ78STJ2g3ilQ5WQZeQDaHs4lmIvjI1OQ21VLj6vFN4snvp6Wjvo1zJHFZ7
    5T40vRLUViBFkl+TGGRAsVH1vs+xayiucTrkPN+a5MUCgYEA9aNVjCt08Ub9eexP
    2wTZBGrYwOO9SMIW34/GWFvHZ8qw8JCMYUNzH1SSWtps4qsbVxkgHy86PN0KBTCr
    dTOwVKKqmXMvX8iA4boyI0f/ZpFYlrsAHW2l8PJDOi4I5tKQOJMH1VuHeGggz0+G
    kTyMlyY25ThlmRr0N9RjNQyYE58CgYEAxABNfkBAGEBFCtMQmr4NpquxMTcJhsOp
    RSizUIjIJGU/kf9wv7DezY6FfnIUm/XErUoweuHtkByY+1CsISRZ/L1FTISKvCNE
    0d8Cpa1enpLIEtOoMRRNag8puvT5Ji2OBc2izRAStd5ZED/coSYDFx8HGKXNJSyb
    DJCIgkU/b3cCgYEAmoLLZQhQ3xRQjUjgUlySRf0PqwWWIxYzXR0LHrlcjSUqd6f1
    JZlP6P1BsnSC2XHYGMltMzB56Z8AlpMuxuJkoFhSB4Q04IM2zsZYk2jOdq4mk2m9
    gMVgBFffgdFDOC5rGasi2kpgxJR7TuwvMVxs8wbOsRDwl4Yk6Jlobg4l+vECgYAw
    jc6kpu/50foIi27ClrA1CLVVdsfiXZgSLNn26luCQJ614SyiIAOhslu5jjMyy3hU
    YVuPJWa/W4Y+Q6bQcvvj01NWeEMSBj6nKvKx7jfRWpU7rLkup1PiIS16RfNulLxp
    DZ7147Ru30z67IcQWKVNVf9hCLnAKsOiIi/e7Z6gUwKBgC1rPumogDiYdOp1iG6F
    xjYrcpz+z3ZgRWzDTMirFFVr85iziwl0CLG25Ljc1nET6aMghQBwKW5bUDp2XOw1
    E6nRa8VbahW2OCMTVImovSvumnQoh+StI2kbeWHsDa0Vv4lqEZ1TzLvIyDLUHRoB
    ixNAUSl7OMwLjxHDGTpdFHr3"""

def main():
    if len( sys.argv ) > 1 and sys.argv[1] == "test":
        sys.argv.pop()
        unittest.main()    
        return

    



if __name__ == '__main__':
    main()