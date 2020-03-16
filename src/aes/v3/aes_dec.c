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

void aes_dec_block (
    uint8_t    pt[16],
    uint8_t    ct[16],
    uint32_t * rk,
    int nr
) {
    uint32_t t0, t1, t2, t3;                //  even round state registers
    uint32_t u0, u1, u2, u3;                //  odd round state registers
    const uint32_t *kp = &rk[4 * nr];       //  key pointer
    
    U8_TO_U32_LE(t0, ct,  0) 
    U8_TO_U32_LE(t1, ct,  4) 
    U8_TO_U32_LE(t2, ct,  8) 
    U8_TO_U32_LE(t3, ct, 12) 

    t0 ^= kp[0];
    t1 ^= kp[1];
    t2 ^= kp[2];
    t3 ^= kp[3];
    
    kp -= 8;

    while (1) {
        u0 = kp[4];                         //  fetch odd subkey
        u1 = kp[5];
        u2 = kp[6];
        u3 = kp[7];

        u0 = _saes_v3_decsm(t0, u0, 0); //  AES decryption round, 16 instr
        u0 = _saes_v3_decsm(t3, u0, 1);
        u0 = _saes_v3_decsm(t2, u0, 2);
        u0 = _saes_v3_decsm(t1, u0, 3);

        u1 = _saes_v3_decsm(t1, u1, 0);
        u1 = _saes_v3_decsm(t0, u1, 1);
        u1 = _saes_v3_decsm(t3, u1, 2);
        u1 = _saes_v3_decsm(t2, u1, 3);

        u2 = _saes_v3_decsm(t2, u2, 0);
        u2 = _saes_v3_decsm(t1, u2, 1);
        u2 = _saes_v3_decsm(t0, u2, 2);
        u2 = _saes_v3_decsm(t3, u2, 3);

        u3 = _saes_v3_decsm(t3, u3, 0);
        u3 = _saes_v3_decsm(t2, u3, 1);
        u3 = _saes_v3_decsm(t1, u3, 2);
        u3 = _saes_v3_decsm(t0, u3, 3);

        t0 = kp[0];                         //  fetch even subkey
        t1 = kp[1];
        t2 = kp[2];
        t3 = kp[3];

        if (kp == rk)                       //  final round
            break;
        kp -= 8;

        t0 = _saes_v3_decsm(u0, t0, 0); //  AES decryption round, 16 instr
        t0 = _saes_v3_decsm(u3, t0, 1);
        t0 = _saes_v3_decsm(u2, t0, 2);
        t0 = _saes_v3_decsm(u1, t0, 3);

        t1 = _saes_v3_decsm(u1, t1, 0);
        t1 = _saes_v3_decsm(u0, t1, 1);
        t1 = _saes_v3_decsm(u3, t1, 2);
        t1 = _saes_v3_decsm(u2, t1, 3);

        t2 = _saes_v3_decsm(u2, t2, 0);
        t2 = _saes_v3_decsm(u1, t2, 1);
        t2 = _saes_v3_decsm(u0, t2, 2);
        t2 = _saes_v3_decsm(u3, t2, 3);

        t3 = _saes_v3_decsm(u3, t3, 0);
        t3 = _saes_v3_decsm(u2, t3, 1);
        t3 = _saes_v3_decsm(u1, t3, 2);
        t3 = _saes_v3_decsm(u0, t3, 3);
    }

    t0 = _saes_v3_decs(u0, t0, 0);   //  final decryption round, 16 ins.
    t0 = _saes_v3_decs(u3, t0, 1);
    t0 = _saes_v3_decs(u2, t0, 2);
    t0 = _saes_v3_decs(u1, t0, 3);

    t1 = _saes_v3_decs(u1, t1, 0);
    t1 = _saes_v3_decs(u0, t1, 1);
    t1 = _saes_v3_decs(u3, t1, 2);
    t1 = _saes_v3_decs(u2, t1, 3);

    t2 = _saes_v3_decs(u2, t2, 0);
    t2 = _saes_v3_decs(u1, t2, 1);
    t2 = _saes_v3_decs(u0, t2, 2);
    t2 = _saes_v3_decs(u3, t2, 3);

    t3 = _saes_v3_decs(u3, t3, 0);
    t3 = _saes_v3_decs(u2, t3, 1);
    t3 = _saes_v3_decs(u1, t3, 2);
    t3 = _saes_v3_decs(u0, t3, 3);

    U32_TO_U8_LE(pt , t0,  0);                      //  write plaintext block
    U32_TO_U8_LE(pt , t1,  4);
    U32_TO_U8_LE(pt , t2,  8);
    U32_TO_U8_LE(pt , t3, 12);
}


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
