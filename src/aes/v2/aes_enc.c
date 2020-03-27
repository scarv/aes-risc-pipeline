
/*!
@addtogroup crypto_block_aes_zscrypto_v2 AES ZSCrypto V2
@ingroup crypto_block_aes
@{
*/

#include "aes.h"
#include "intrinsics.h"

//! AES Round constants
static const uint8_t round_const[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 
};

/*!
*/
void    aes_enc_key_schedule (
    uint32_t    rk [16],
    uint8_t     ck [16],
    const int   Nk , //!< Number of words in the key.
    const int   Nr   //!< Number of rounds.
){
    const int        Nb =  4;

    for(int i = 0; i < Nb; i ++) {
        
        U8_TO_U32_LE(rk[i], ck,  4*i);

    }
    
    for(int i = 4; i < Nk*(Nr+1); i += 1) {

        uint32_t temp = rk[i-1];

        if( i % Nk == 0 ) {

            temp  = ROTR32(temp, 8);
            temp  = _saes_v2_sub_enc(temp,temp);
            temp ^= round_const[i/Nk];

        } else if ( (Nk > 6) && (i % Nk == 4)) {
            
            temp  = _saes_v2_sub_enc(temp,temp);

        }

        rk[i] = rk[i-Nk] ^ temp;
    }
}


/*!
*/
void    aes_enc_block(
    uint8_t     ct [16],
    uint8_t     pt [16],
    uint32_t  * rk,
    int         nr
){
    int round = 0;

    uint32_t *kp = rk;

    uint32_t u0, u1, u2, u3;
    uint32_t t0, t1, t2, t3;

    U8_TO_U32_LE(t0, pt, 0);
    U8_TO_U32_LE(t1, pt, 4);
    U8_TO_U32_LE(t2, pt, 8);
    U8_TO_U32_LE(t3, pt,12);

    t0 ^= rk[0];
    t1 ^= rk[1];
    t2 ^= rk[2];
    t3 ^= rk[3];


    kp += 4;

    for(round = 1; round < nr; round ++) {
        
        u0 = _saes_v2_sub_enc(t0, t1);      // SubBytes & Partial ShiftRows
        u1 = _saes_v2_sub_enc(t2, t3);
        u2 = _saes_v2_sub_enc(t1, t2);
        u3 = _saes_v2_sub_enc(t3, t0);

        t0 = _saes_v2_mix_enc(u0, u1);      // Partial ShiftRows & MixColumns
        t1 = _saes_v2_mix_enc(u2, u3);
        t2 = _saes_v2_mix_enc(u1, u0);
        t3 = _saes_v2_mix_enc(u3, u2);
    
        t0 ^= kp[0];                        // AddRoundKey
        t1 ^= kp[1];
        t2 ^= kp[2];
        t3 ^= kp[3];
    
        kp += 4;

    }

    u0 = _saes_v2_sub_enc(t0, t1);          // SubBytes & Partial ShiftRows
    u1 = _saes_v2_sub_enc(t2, t3);
    u2 = _saes_v2_sub_enc(t1, t2);
    u3 = _saes_v2_sub_enc(t3, t0);


    t0 = (u0 & 0x0000FFFF) | (u1 & 0xFFFF0000); // Finish shift rows
    t1 = (u2 & 0x0000FFFF) | (u3 & 0xFFFF0000);
    t2 = (u1 & 0x0000FFFF) | (u0 & 0xFFFF0000);
    t3 = (u3 & 0x0000FFFF) | (u2 & 0xFFFF0000);

    t0 ^= kp[0];                            // AddRoundKey
    t1 ^= kp[1];
    t2 ^= kp[2];
    t3 ^= kp[3];
    
    U32_TO_U8_LE(ct , t0,  0);               // Write ciphertext block
    U32_TO_U8_LE(ct , t1,  4);
    U32_TO_U8_LE(ct , t2,  8);
    U32_TO_U8_LE(ct , t3, 12);
}

void    aes_128_enc_key_schedule (
    uint32_t    rk [AES_128_RK_WORDS],
    uint8_t     ck [AES_128_CK_BYTES] 
){
    uint32_t    t0,t1,t2,t3,tr;

    U8_TO_U32_LE(t0, ck,  0);
    U8_TO_U32_LE(t1, ck,  4);
    U8_TO_U32_LE(t2, ck,  8);
    U8_TO_U32_LE(t3, ck, 12);

    uint32_t *rkp= rk;
    uint32_t *rke= &rk[40];
    uint8_t  *rcp= &round_const[1];
    
    while(1) {

        rkp[0] = t0;
        rkp[1] = t1;
        rkp[2] = t2;
        rkp[3] = t3;

        if(rke == rkp) {
            return;
        }

        rkp += 4;

        t0 ^= (uint32_t)*rcp++;
        tr  = ROTR32(t3, 8);
        tr  = _saes_v2_sub_enc(tr,tr);
        t0 ^= tr;

        t1 ^= t0;
        t2 ^= t1;
        t3 ^= t2;
    }
}

void    aes_192_enc_key_schedule (
    uint32_t    rk [AES_128_RK_WORDS],
    uint8_t     ck [AES_128_CK_BYTES] 
){
    aes_enc_key_schedule(rk, ck, AES_192_NK, AES_192_NR);
}

void    aes_256_enc_key_schedule (
    uint32_t    rk [AES_128_RK_WORDS],
    uint8_t     ck [AES_128_CK_BYTES] 
){
    aes_enc_key_schedule(rk, ck, AES_256_NK, AES_256_NR);
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
