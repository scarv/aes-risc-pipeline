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

void aes_enc_block (
    uint8_t   ct[16],
    uint8_t   pt[16],
    uint32_t *rk,
    int nr
) {
    uint32_t t0, t1, t2, t3;                //  even round state registers
    uint32_t u0, u1, u2, u3;                //  odd round state registers
    const uint32_t *kp = &rk[4 * nr];       //  key pointer as loop condition

    AES_LOAD_STATE(t0,t1,t2,t3,pt);

    t0 ^= rk[0];
    t1 ^= rk[1];
    t2 ^= rk[2];
    t3 ^= rk[3];

    while (1) {                             //  double round

        u0 = rk[4];                         //  fetch odd subkey
        u1 = rk[5];
        u2 = rk[6];
        u3 = rk[7];

        u0 = _saes_v3_encsm(t0, u0, 0); //  AES round, 16 instructions
        u0 = _saes_v3_encsm(t1, u0, 1);
        u0 = _saes_v3_encsm(t2, u0, 2);
        u0 = _saes_v3_encsm(t3, u0, 3);

        u1 = _saes_v3_encsm(t1, u1, 0);
        u1 = _saes_v3_encsm(t2, u1, 1);
        u1 = _saes_v3_encsm(t3, u1, 2);
        u1 = _saes_v3_encsm(t0, u1, 3);

        u2 = _saes_v3_encsm(t2, u2, 0);
        u2 = _saes_v3_encsm(t3, u2, 1);
        u2 = _saes_v3_encsm(t0, u2, 2);
        u2 = _saes_v3_encsm(t1, u2, 3);

        u3 = _saes_v3_encsm(t3, u3, 0);
        u3 = _saes_v3_encsm(t0, u3, 1);
        u3 = _saes_v3_encsm(t1, u3, 2);
        u3 = _saes_v3_encsm(t2, u3, 3);

        t0 = rk[8];                         //  fetch even subkey
        t1 = rk[9];
        t2 = rk[10];
        t3 = rk[11];

        rk += 8;                            //  step key pointer
        if (rk == kp)                       //  final round ?
            break;

        t0 = _saes_v3_encsm(u0, t0, 0); //  final encrypt round, 16 ins.
        t0 = _saes_v3_encsm(u1, t0, 1);
        t0 = _saes_v3_encsm(u2, t0, 2);
        t0 = _saes_v3_encsm(u3, t0, 3);

        t1 = _saes_v3_encsm(u1, t1, 0);
        t1 = _saes_v3_encsm(u2, t1, 1);
        t1 = _saes_v3_encsm(u3, t1, 2);
        t1 = _saes_v3_encsm(u0, t1, 3);

        t2 = _saes_v3_encsm(u2, t2, 0);
        t2 = _saes_v3_encsm(u3, t2, 1);
        t2 = _saes_v3_encsm(u0, t2, 2);
        t2 = _saes_v3_encsm(u1, t2, 3);

        t3 = _saes_v3_encsm(u3, t3, 0);
        t3 = _saes_v3_encsm(u0, t3, 1);
        t3 = _saes_v3_encsm(u1, t3, 2);
        t3 = _saes_v3_encsm(u2, t3, 3);
    }

    t0 = _saes_v3_encs(u0, t0, 0);     //  final round is different
    t0 = _saes_v3_encs(u1, t0, 1);
    t0 = _saes_v3_encs(u2, t0, 2);
    t0 = _saes_v3_encs(u3, t0, 3);

    t1 = _saes_v3_encs(u1, t1, 0);
    t1 = _saes_v3_encs(u2, t1, 1);
    t1 = _saes_v3_encs(u3, t1, 2);
    t1 = _saes_v3_encs(u0, t1, 3);

    t2 = _saes_v3_encs(u2, t2, 0);
    t2 = _saes_v3_encs(u3, t2, 1);
    t2 = _saes_v3_encs(u0, t2, 2);
    t2 = _saes_v3_encs(u1, t2, 3);

    t3 = _saes_v3_encs(u3, t3, 0);
    t3 = _saes_v3_encs(u0, t3, 1);
    t3 = _saes_v3_encs(u1, t3, 2);
    t3 = _saes_v3_encs(u2, t3, 3);

    U32_TO_U8_LE(ct , t0,  0);                 //  write ciphertext block
    U32_TO_U8_LE(ct , t1,  4);
    U32_TO_U8_LE(ct , t2,  8);
    U32_TO_U8_LE(ct , t3, 12);
}

/*
void aes_128_enc_key_schedule (
    uint32_t rk[44],
    uint8_t  ck[16]
) {
    uint32_t t0, t1, t2, t3, tr;            //  subkey registers
    const uint32_t *rke = &rk[44 - 4];      //  end pointer
    const uint8_t *rc = aes_rcon;           //  round constants

    AES_LOAD_STATE(t0,t1,t2,t3,ck);

    while (1) {

        rk[0] = t0;                         //  store subkey
        rk[1] = t1;
        rk[2] = t2;
        rk[3] = t3;

        if (rk == rke)                      //  end condition
            return;
        rk += 4;                            //  step pointer by one subkey

        t0 ^= (uint32_t) *rc++;             //  round constant
        tr = ROTL32(t3, 24);                //  rotate 8 bits (little endian!)
        t0 = _saes_v3_encs(tr, t0, 0);   //  SubWord()
        t0 = _saes_v3_encs(tr, t0, 1);   //
        t0 = _saes_v3_encs(tr, t0, 2);   //
        t0 = _saes_v3_encs(tr, t0, 3);   //
        t1 ^= t0;
        t2 ^= t1;
        t3 ^= t2;
    }
}
*/

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
