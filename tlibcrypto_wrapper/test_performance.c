#include <stdio.h>

#include <sgx_tcrypto.h>



typedef enum 
{
    STATUS_SUCCESS  = 0,
    STATUS_ERROR    = 1,
} Status;

Status GenerateKeyPairECDSA(   sgx_ec256_private_t*      privateKey, 
                               sgx_ec256_public_t*       publicKey   )
{
    sgx_ecc_state_handle_t context;
    if( SGX_SUCCESS !=  sgx_ecc256_open_context( &context) )
        return STATUS_ERROR;
 
    if( SGX_SUCCESS !=  sgx_ecc256_create_key_pair( privateKey, publicKey, context) )
        return STATUS_ERROR;

    if( SGX_SUCCESS !=  sgx_ecc256_close_context( context ) )
        return STATUS_ERROR;
    
    return STATUS_SUCCESS;
}


Status SignECDSA(   uint8_t                 *data,
                    uint32_t                dataSize, 
                    sgx_ec256_private_t     *privateKey,
                    sgx_ec256_signature_t   *signature )
{
    sgx_ecc_state_handle_t          context             = NULL;
      
    if( SGX_SUCCESS !=  sgx_ecc256_open_context( &context) || NULL == context )
        return STATUS_ERROR;
 
    if( SGX_SUCCESS !=  sgx_ecdsa_sign( data, 
                                        dataSize,
                                        privateKey,
                                        signature,
                                        context ) ) {
        sgx_ecc256_close_context( context );
        return STATUS_ERROR;    
    }

    if( SGX_SUCCESS !=  sgx_ecc256_close_context( context ) )
        return STATUS_ERROR;

    return STATUS_SUCCESS;
}

inline __attribute__((always_inline))  uint64_t rdtscp(void)
{
        unsigned int low, high;

        asm volatile("rdtscp" : "=a" (low), "=d" (high));

        return low | ((uint64_t)high) << 32;
}

void TestECDSAPerformance()
{
	sgx_ec256_private_t privateKey;
	sgx_ec256_public_t  publicKey;

	printf("GenerateKeyPairECDSA --> %d\n", GenerateKeyPairECDSA( &privateKey, &publicKey) );

	sgx_ec256_signature_t   signature;
	uint8_t					data[ 1024 ] = {0};

	Status ret = SignECDSA( data,
                    		sizeof( data ), 
                    		&privateKey,
                    		&signature );

	printf( "SignECDSA --> %d\n", ret );

	const uint32_t NUM_OPERATIONS = 1000000;
	uint64_t startTime = 0;
	uint64_t totalTime = 0;

	startTime = rdtscp();
	for( int i = 0; i < NUM_OPERATIONS; ++i ) {
		SignECDSA( 	data,
            		sizeof( data ), 
            		&privateKey,
            		&signature );
	}
	totalTime = rdtscp() - startTime;

	printf("Cycles per ECDSA sig: %f\n", (double)totalTime / NUM_OPERATIONS );

	double CPU_FREQUENCY = 4e9;
	double totalSeconds  = (double)totalTime / CPU_FREQUENCY ;
	printf( "Signatures per second: %f\n", NUM_OPERATIONS / totalSeconds );
}

int main()
{
	printf( "Hi!\n" );
	// TestECDSAPerformance()
	
	const  uint8_t* NO_ADD_POINTER                    = NULL;
    const  uint32_t NO_ADD_SIZE                       = 0;

	const 	sgx_aes_gcm_128bit_key_t key 	= {0};
	uint8_t			data[ 1024 * 1]  			= {0};
	uint8_t			cipher[ 1024 * 1] 			= {0};
    const uint8_t 	iv[ 12 ] 				= {0};
   
    sgx_aes_gcm_128bit_tag_t mac;

	if( SGX_SUCCESS != sgx_rijndael128GCM_encrypt( &key,
                                                   data,
                                                   sizeof( data ),
                                                   cipher,
                                                   iv,
                                                   sizeof( iv ),
                                                   NO_ADD_POINTER,
                                                   NO_ADD_SIZE,
                                                   &mac ) )
        printf("Error running sgx_rijndael128GCM_encrypt\n"); 
    else 
    	printf("Suceeded running sgx_rijndael128GCM_encrypt\n" );   

    const uint32_t NUM_OPERATIONS = 1000000;
	uint64_t startTime = 0;
	uint64_t totalTime = 0;

	startTime = rdtscp();
	for( int i = 0; i < NUM_OPERATIONS; ++i ) {
		sgx_rijndael128GCM_encrypt(&key,
                                   data,
                                   sizeof( data ),
                                   cipher,
                                   iv,
                                   sizeof( iv ),
                                   NO_ADD_POINTER,
                                   NO_ADD_SIZE,
                                   &mac );
	}
	totalTime = rdtscp() - startTime;

	printf("Cycles per AES_GCM sig: %f\n", (double)totalTime / NUM_OPERATIONS );

	double CPU_FREQUENCY = 4e9;
	double totalSeconds  = (double)totalTime / CPU_FREQUENCY ;
	printf( "AES_GCM per second: %f\n", NUM_OPERATIONS / totalSeconds );
}