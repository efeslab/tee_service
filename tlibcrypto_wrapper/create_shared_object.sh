#!/bin/bash
set -v
set -e

SGX_SOURCE_PATH=/home/ofir/dev/git/linux-sgx/
IPP_BINARIES_PATH=$SGX_SOURCE_PATH/external/ippcp_internal/lib/linux/intel64/

g++ -c -fPIC sgx_memset_s.cpp 
g++ -c -fPIC sgx_read_rand.cpp -I/opt/intel/sgxsdk/include/ -I$SGX_SOURCE_PATH/common/inc/internal/ -Irdrand/
g++ -c -fPIC ecp.cpp -I$SGX_SOURCE_PATH/common/inc/internal -I$SGX_SOURCE_PATH/common/inc/ -I.
gcc -c -fPIC consttime_memequal.c

cd rdrand; make; cd -
# cd $SGX_SOURCE_PATH/external/crypto_px ; make; cd -

cd tlibcrypto
g++ -c init_crypto_lib.cpp -fPIC -I$SGX_SOURCE_PATH/common/inc/internal -I$SGX_SOURCE_PATH/common/inc -I$SGX_SOURCE_PATH/common/inc/tlibc -I$SGX_SOURCE_PATH/external/crypto_px/include
g++ -c sgx_aes_ctr.cpp -fPIC -I$SGX_SOURCE_PATH/common/inc/internal -I$SGX_SOURCE_PATH/common/inc -I$SGX_SOURCE_PATH/common/inc/tlibc -I$SGX_SOURCE_PATH/external/crypto_px/include
g++ -c sgx_aes_gcm.cpp -fPIC -I$SGX_SOURCE_PATH/common/inc/internal -I$SGX_SOURCE_PATH/common/inc -I$SGX_SOURCE_PATH/common/inc/tlibc -I$SGX_SOURCE_PATH/external/crypto_px/include
g++ -c sgx_cmac128.cpp -fPIC -I$SGX_SOURCE_PATH/common/inc/internal -I$SGX_SOURCE_PATH/common/inc -I$SGX_SOURCE_PATH/common/inc/tlibc -I$SGX_SOURCE_PATH/external/crypto_px/include
g++ -c sgx_ecc256.cpp -fPIC -I$SGX_SOURCE_PATH/common/inc/internal -I$SGX_SOURCE_PATH/common/inc -I$SGX_SOURCE_PATH/common/inc/tlibc -I$SGX_SOURCE_PATH/external/crypto_px/include
g++ -c sgx_ecc256_common.cpp -fPIC -I$SGX_SOURCE_PATH/common/inc/internal -I$SGX_SOURCE_PATH/common/inc -I$SGX_SOURCE_PATH/common/inc/tlibc -I$SGX_SOURCE_PATH/external/crypto_px/include
g++ -c sgx_ecc256_ecdsa.cpp -fPIC -I$SGX_SOURCE_PATH/common/inc/internal -I$SGX_SOURCE_PATH/common/inc -I$SGX_SOURCE_PATH/common/inc/tlibc -I$SGX_SOURCE_PATH/external/crypto_px/include
g++ -c sgx_sha256.cpp -fPIC -I$SGX_SOURCE_PATH/common/inc/internal -I$SGX_SOURCE_PATH/common/inc -I$SGX_SOURCE_PATH/common/inc/tlibc -I$SGX_SOURCE_PATH/external/crypto_px/include
g++ -c sgx_sha256_msg.cpp -fPIC -I$SGX_SOURCE_PATH/common/inc/internal -I$SGX_SOURCE_PATH/common/inc -I$SGX_SOURCE_PATH/common/inc/tlibc -I$SGX_SOURCE_PATH/external/crypto_px/include
g++ -c tcrypto_version.cpp -fPIC -I$SGX_SOURCE_PATH/common/inc/internal -I$SGX_SOURCE_PATH/common/inc -I$SGX_SOURCE_PATH/common/inc/tlibc -I$SGX_SOURCE_PATH/external/crypto_px/include
cd -
 
g++   -shared	-Wl,--whole-archive \
				sgx_memset_s.o \
				consttime_memequal.o  \
				sgx_read_rand.o \
				rdrand/rdrand.o  \
				ecp.o 							\
				./tlibcrypto/init_crypto_lib.o \
				./tlibcrypto/sgx_aes_ctr.o \
				./tlibcrypto/sgx_aes_gcm.o \
				./tlibcrypto/sgx_cmac128.o \
				./tlibcrypto/sgx_ecc256.o \
				./tlibcrypto/sgx_ecc256_common.o \
				./tlibcrypto/sgx_ecc256_ecdsa.o \
				./tlibcrypto/sgx_sha256.o \
				./tlibcrypto/sgx_sha256_msg.o \
				./tlibcrypto/tcrypto_version.o \
				$IPP_BINARIES_PATH/libippcp.a \
				$IPP_BINARIES_PATH/libippcore.a \
				-Wl,--no-whole-archive -o crypto_wrapper.so

# g++ test_performance.c -I$SGX_SOURCE_PATH/common/inc  \
#  				sgx_memset_s.o \
# 				consttime_memequal.o  \
# 				sgx_read_rand.o \
# 				rdrand/rdrand.o  \
# 				ecp.o 							\
# 				./tlibcrypto/init_crypto_lib.o \
# 				./tlibcrypto/sgx_aes_ctr.o \
# 				./tlibcrypto/sgx_aes_gcm.o \
# 				./tlibcrypto/sgx_cmac128.o \
# 				./tlibcrypto/sgx_ecc256.o \
# 				./tlibcrypto/sgx_ecc256_common.o \
# 				./tlibcrypto/sgx_ecc256_ecdsa.o \
# 				./tlibcrypto/sgx_sha256.o \
# 				./tlibcrypto/sgx_sha256_msg.o \
# 				./tlibcrypto/tcrypto_version.o \
# 				$IPP_BINARIES_PATH/libippcp.a \
# 				$IPP_BINARIES_PATH/libippcore.a \
# 				-o test_performance
				

