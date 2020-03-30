//  aes_dec.c
//  2020-01-22  Markku-Juhani O. Saarinen <mjos@pqhsield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.


/*!
@addtogroup crypto_block_aes_reference AES Reference
@brief Reference implementation of AES.
@ingroup crypto_block_aes
@{
*/

#include "aes.h"
#include "intrinsics.h"

//  Decrypt rounds. Implements AES-128/192/256 depending on nr = {10,12,14}
extern void aes_dec_block (
    uint8_t    pt[16],
    uint8_t    ct[16],
    uint32_t * rk,
    int nr
);


//  Helper: apply inverse mixcolumns to a vector
//  If decryption keys are computed in the fly (inverse key schedule), there's
//  no need for the encryption instruction (but you need final subkey).

static void aes_dec_invmc(
    uint32_t *v,
    size_t len
) {
    size_t i;
    uint32_t x;
    uint32_t t;

    for (i = 0; i < len; i++) {
        x = v[i];

        t = _saes_v3_encs(x,0,0);           // Sub Word
        t = _saes_v3_encs(x,t,1);
        t = _saes_v3_encs(x,t,2);
        t = _saes_v3_encs(x,t,3);

        x = _saes_v3_decsm(t, 0, 0);        // Just want inv MixCol()
        x = _saes_v3_decsm(t, x, 1);        //
        x = _saes_v3_decsm(t, x, 2);        //
        x = _saes_v3_decsm(t, x, 3);        //

        v[i] = x;
    }
}


void    aes_128_dec_key_schedule (
    uint32_t    rk [AES_128_RK_WORDS],
    uint8_t     ck [AES_128_CK_BYTES] 
){
    aes_128_enc_key_schedule(rk, ck);
    aes_dec_invmc(rk + 4, AES_128_RK_WORDS - 8);
}

void    aes_192_dec_key_schedule (
    uint32_t    rk [AES_256_RK_WORDS],
    uint8_t     ck [AES_256_CK_BYTES] 
){
    aes_192_enc_key_schedule(rk, ck);
    aes_dec_invmc(rk + 4, AES_192_RK_WORDS - 8);
}

void    aes_256_dec_key_schedule (
    uint32_t    rk [AES_256_RK_WORDS],
    uint8_t     ck [AES_256_CK_BYTES] 
){
    aes_256_enc_key_schedule(rk, ck);
    aes_dec_invmc(rk + 4, AES_256_RK_WORDS - 8);
}

void    aes_128_dec_block(
    uint8_t     pt [              16],
    uint8_t     ct [              16],
    uint32_t    rk [AES_128_RK_WORDS] 
){
    aes_dec_block (pt, ct, rk, AES_128_NR);
}

void    aes_192_dec_block(
    uint8_t     pt [              16],
    uint8_t     ct [              16],
    uint32_t    rk [AES_192_RK_WORDS] 
){
    aes_dec_block (pt, ct, rk, AES_192_NR);
}

void    aes_256_dec_block(
    uint8_t     pt [              16],
    uint8_t     ct [              16],
    uint32_t    rk [AES_256_RK_WORDS] 
){
    aes_dec_block (pt, ct, rk, AES_256_NR);
}


//!@}
