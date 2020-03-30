//  aes_enc.c
//  2020-01-22  Markku-Juhani O. Saarinen <mjos@pqhsield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.


/*!
@addtogroup crypto_block_aes_zscrypto_v3 AES Proposal 3
@brief implementation of AES using the V3 proposals.
@ingroup crypto_block_aes
@{
*/

#include "aes.h"
#include "intrinsics.h"

//  round constants -- just iterations of the xtime() LFSR
static const uint8_t aes_rcon[] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

//  Encrypt rounds. Implements AES-128/192/256 depending on nr = {10,12,14}
extern void aes_enc_block (
    uint8_t   ct[16],
    uint8_t   pt[16],
    uint32_t *rk,
    int nr
);

//  Key schedule for AES-192 encryption.
void aes_192_enc_key_schedule(
    uint32_t rk[52],
    uint8_t  ck[24]
) {
    uint32_t t0, t1, t2, t3, t4, t5, tr;    //  subkey registers
    const uint32_t *rke = &rk[52 - 4];      //  end pointer
    const uint8_t *rc = aes_rcon;           //  round constants

    U8_TO_U32_LE(t0, ck,  0);              //  load secret key
    U8_TO_U32_LE(t1, ck,  4);
    U8_TO_U32_LE(t2, ck,  8);
    U8_TO_U32_LE(t3, ck, 12);
    U8_TO_U32_LE(t4, ck, 16);
    U8_TO_U32_LE(t5, ck, 20);

    while (1) {

        rk[0] = t0;                         //  store subkey (or part)
        rk[1] = t1;
        rk[2] = t2;
        rk[3] = t3;
        if (rk == rke)                      //  end condition
            return;
        rk[4] = t4;
        rk[5] = t5;
        rk += 6;                            //  step pointer by 1.5 subkeys

        t0 ^= (uint32_t) *rc++;             //  round constant
        tr = ROTL32(t5, 24);                //  rotate 8 bits (little endian!)
        t0 = _saes_v3_encs(tr, t0, 0);   //  SubWord()
        t0 = _saes_v3_encs(tr, t0, 1);   //
        t0 = _saes_v3_encs(tr, t0, 2);   //
        t0 = _saes_v3_encs(tr, t0, 3);   //

        t1 ^= t0;
        t2 ^= t1;
        t3 ^= t2;
        t4 ^= t3;
        t5 ^= t4;
    }
}

//  Key schedule for AES-256 encryption.
void aes_256_enc_key_schedule(
    uint32_t rk[60],
    uint8_t  ck[32]
){
    uint32_t t0, t1, t2, t3, t4, t5, t6, t7, tr; // subkey registers
    const uint32_t *rke = &rk[60 - 4];      //  end pointer
    const uint8_t *rc = aes_rcon;           //  round constants

    U8_TO_U32_LE(t0, ck,  0);              //  load secret key
    U8_TO_U32_LE(t1, ck,  4);
    U8_TO_U32_LE(t2, ck,  8);
    U8_TO_U32_LE(t3, ck, 12);
    U8_TO_U32_LE(t4, ck, 16);
    U8_TO_U32_LE(t5, ck, 20);
    U8_TO_U32_LE(t6, ck, 24);
    U8_TO_U32_LE(t7, ck, 28);

    rk[0] = t0;                             //  store first subkey
    rk[1] = t1;
    rk[2] = t2;
    rk[3] = t3;

    while (1) {

        rk[4] = t4;                         //  store odd subkey
        rk[5] = t5;
        rk[6] = t6;
        rk[7] = t7;
        rk += 8;                            //  step pointer by 2 subkeys

        t0 ^= (uint32_t) *rc++;             //  round constant
        tr = ROTL32(t7, 24);                //  rotate 8 bits (little endian!)
        t0 = _saes_v3_encs(tr, t0, 0);   //  SubWord()
        t0 = _saes_v3_encs(tr, t0, 1);   //
        t0 = _saes_v3_encs(tr, t0, 2);   //
        t0 = _saes_v3_encs(tr, t0, 3);   //
        t1 ^= t0;
        t2 ^= t1;
        t3 ^= t2;

        rk[0] = t0;                         //  store even subkey
        rk[1] = t1;
        rk[2] = t2;
        rk[3] = t3;
        if (rk == rke)                      //  end condition
            return;

        t0 = _saes_v3_encs(tr, t0, 0);   //  SubWord()
        t0 = _saes_v3_encs(tr, t0, 1);   //
        t0 = _saes_v3_encs(tr, t0, 2);   //
        t0 = _saes_v3_encs(tr, t0, 3);   //
        t5 ^= t4;
        t6 ^= t5;
        t7 ^= t6;
    }
}

void    aes_128_enc_block(
    uint8_t     ct [              16],
    uint8_t     pt [              16],
    uint32_t    rk [AES_128_RK_WORDS] 
){
    aes_enc_block (ct, pt, rk, AES_128_NR);
}

void    aes_192_enc_block(
    uint8_t     ct [              16],
    uint8_t     pt [              16],
    uint32_t    rk [AES_192_RK_WORDS] 
){
    aes_enc_block (ct, pt, rk, AES_192_NR);
}

void    aes_256_enc_block(
    uint8_t     ct [              16],
    uint8_t     pt [              16],
    uint32_t    rk [AES_256_RK_WORDS] 
){
    aes_enc_block (ct, pt, rk, AES_256_NR);
}


//!@}
