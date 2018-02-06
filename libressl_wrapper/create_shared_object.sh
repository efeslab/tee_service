#!/bin/bash
set -v
set -e

LIBRESSL_SOURCE_PATH=/home/ofir/sgx/libressl-2.4.4/
 
g++   -shared	-Wl,--whole-archive \
				$LIBRESSL_SOURCE_PATH/crypto/.libs/libcrypto.a \
				-Wl,--no-whole-archive -o libressl_wrapper.so
				

