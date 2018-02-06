//Author: Ofir Weisse, www.OfirWeisse.com, email: oweisse (at) umich (dot) edu
//Based on ISCA 2017 "HotCalls" paper. 
//Link to the paper can be found at http://www.ofirweisse.com/previous_work.html
//If you make nay use of this code for academic purpose, please cite the paper. 

// MIT License

// Copyright (c) 2016 oweisse

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.


#ifndef __FAST_SGX_CALLS_H
#define __FAST_SGX_CALLS_H


// #include <stdlib.h>
#include <sgx_spinlock.h>
#include <stdbool.h>
#include <sgx_eid.h>
#include <sgx_error.h>
// #include "utils.h"


#pragma GCC diagnostic ignored "-Wunused-function"

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned long int pthread_t;

typedef struct {
    pthread_t       responderThread;
    sgx_spinlock_t  spinlock;
    void*           data;
    uint16_t        callID;
    bool            keepPolling;
    bool            runFunction;
    bool            isDone;
    bool            busy;
} HotCall;

typedef struct {
    HotCall          *hotCall;
    sgx_enclave_id_t enclaveID;
} HotCallDispatcher;

typedef struct 
{
    uint16_t numEntries;
    sgx_status_t (**callbacks)(void*);
} HotCallTable;

#define HOTCALL_INITIALIZER  {0, SGX_SPINLOCK_INITIALIZER, NULL, 0, true, false, false, false }

static void HotCall_init( HotCall* hotCall )
{
    hotCall->responderThread    = 0;
    hotCall->spinlock           = SGX_SPINLOCK_INITIALIZER;
    hotCall->data               = NULL; 
    hotCall->callID             = 0;
    hotCall->keepPolling        = true;
    hotCall->runFunction        = false;
    hotCall->isDone             = false;
    hotCall->busy               = false;
}

#ifndef SKIP_MM_PAUSE_DEFINITION
static inline void _mm_pause(void) __attribute__((always_inline));
static inline void _mm_pause(void)
{
    __asm __volatile(
        "pause"
    );
}
#endif


static inline int HotCall_requestCall( HotCall* hotCall, uint16_t callID, void *data )
{
    int i = 0;
    const uint32_t MAX_RETRIES = 10;
    uint32_t numRetries = 0;
    //REquest call
    while( true ) {
        sgx_spin_lock( &hotCall->spinlock );
        if( hotCall->busy == false ) {
            hotCall->busy        = true;
            hotCall->isDone      = false;
            hotCall->runFunction = true;
            hotCall->callID      = callID;
            hotCall->data        = data;
            sgx_spin_unlock( &hotCall->spinlock );
            break;
        }
        //else:
        sgx_spin_unlock( &hotCall->spinlock );

        numRetries++;
        if( numRetries > MAX_RETRIES )
            return -1;

        for( i = 0; i<3; ++i)
            _mm_pause();
    }

    //wait for answer
    while( true )
    {
        sgx_spin_lock( &hotCall->spinlock );
        if( hotCall->isDone == true ){
            hotCall->busy = false;
            sgx_spin_unlock( &hotCall->spinlock );
            break;
        }

        sgx_spin_unlock( &hotCall->spinlock );
        // for( i = 0; i<1; ++i)
        //     _mm_pause();
    }

    return numRetries;
}

static inline int HotCall_requestCall_dontBlock( HotCall* hotCall, uint16_t callID, void *data ) __attribute__((always_inline));
static inline int HotCall_requestCall_dontBlock( HotCall* hotCall, uint16_t callID, void *data )
{
    int i = 0;
    const uint32_t MAX_RETRIES = 10;
    uint32_t numRetries = 0;
    //REquest call
    while( true ) {
        sgx_spin_lock( &hotCall->spinlock );
        if( hotCall->busy == false ) {
            hotCall->busy        = true;
            hotCall->isDone      = false;
            hotCall->runFunction = true;
            hotCall->callID      = callID;
            hotCall->data        = data;
            sgx_spin_unlock( &hotCall->spinlock );
            break;
        }
        //else:
        sgx_spin_unlock( &hotCall->spinlock );

        numRetries++;
        if( numRetries > MAX_RETRIES )
            return -1;

        for( i = 0; i<3; ++i)
            _mm_pause();
    }

    return numRetries;
}

static inline void HotCall_requestCall_waitForResponse( HotCall* hotCall ) __attribute__((always_inline));
static inline void HotCall_requestCall_waitForResponse( HotCall* hotCall )
{
    //wait for answer
    while( true )
    {
        sgx_spin_lock( &hotCall->spinlock );
        if( hotCall->isDone == true ){
            hotCall->busy = false;
            sgx_spin_unlock( &hotCall->spinlock );
            break;
        }

        sgx_spin_unlock( &hotCall->spinlock );
        for( int i = 0; i<3; ++i)
            _mm_pause();
    }
}

static inline void HotCall_waitForCall( HotCall *hotCall, HotCallTable* callTable )  __attribute__((always_inline));
static inline void HotCall_waitForCall( HotCall *hotCall, HotCallTable* callTable ) 
{
    static int i;
    // volatile void *data;
    while( true )
    {
        sgx_spin_lock( &hotCall->spinlock );
        if( hotCall->keepPolling != true ) {
            sgx_spin_unlock( &hotCall->spinlock );
            break;
        }

        if( hotCall->runFunction )
        {
            volatile uint16_t callID = hotCall->callID;
            void              *data  = hotCall->data;
            sgx_spin_unlock( &hotCall->spinlock );

            if( callID < callTable->numEntries ) {
                // printf( "Calling callback %d\n", callID );
                callTable->callbacks[ callID ]( data );
            }
            else {
                // printf( "Invalid callID\n" );
                // exit(42);
            }
            // DoWork( hotCall->data );
            // data = (int*)hotCall->data;
            // printf( "Enclave: Data is at %p\n", data );
            // *data += 1;
            
            sgx_spin_lock( &hotCall->spinlock );
            hotCall->isDone      = true;
            hotCall->runFunction = false;
        }

        sgx_spin_unlock( &hotCall->spinlock );
        for( i = 0; i<3; ++i)
            _mm_pause();
        
        // _mm_pause();
        //     _mm_pause();
        // _mm_pause();
    }
}

static inline void StopResponder( HotCall *hotCall );
static inline void StopResponder( HotCall *hotCall )
{
    sgx_spin_lock( &hotCall->spinlock );
    hotCall->keepPolling = false;
    sgx_spin_unlock( &hotCall->spinlock );
}

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif