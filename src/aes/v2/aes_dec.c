
/*!
@addtogroup crypto_block_aes_zscrypto_v2 AES ZSCrypto V2
@ingroup crypto_block_aes
@{
*/

#include "aes.h"
#include "intrinsics.h"


// Defined in aes/v2/aes_enc.c
extern void    aes_enc_key_schedule (
    uint32_t    rk [16],
    uint8_t     ck [16],
    const int   Nk , //!< Number of words in the key.
    const int   Nr   //!< Number of rounds.
);

/*!
*/
void    aes_dec_key_schedule (
    uint32_t    rk [16],
    uint8_t     ck [16],
    const int  Nk , //!< Number of words in the key.
    const int  Nr   //!< Number of rounds.
){
    aes_enc_key_schedule(rk, ck, Nk, Nr);

    for(int i = 1; i < Nr; i ++) {
        
        uint32_t* t = rk  +  (4*i);

        t[0] = _saes_v2_mix_dec(t[0],t[0]);
        t[1] = _saes_v2_mix_dec(t[1],t[1]);
        t[2] = _saes_v2_mix_dec(t[2],t[2]);
        t[3] = _saes_v2_mix_dec(t[3],t[3]);

    }
}


/*!
@brief Generic single-block AES encrypt function
@param [out] pt - Output plaintext
@param [in]  ct - Input cipher text
@param [in]  rk - The expanded key schedule
@param [in]  nr - Number of decryption rounds to perform.
*/
void    aes_dec_block(
    uint8_t     pt [16],
    uint8_t     ct [16],
    uint32_t  * rk,
    int         nr
){
    int round = 0;

    uint32_t *kp = &rk[4*nr];

    uint32_t t4, t5, t6, t7;
    uint32_t t0, t1, t2, t3;

    U8_TO_U32_LE(t0, ct,  0) 
    U8_TO_U32_LE(t1, ct,  4) 
    U8_TO_U32_LE(t2, ct,  8) 
    U8_TO_U32_LE(t3, ct, 12) 

    t0 ^= kp[0];
    t1 ^= kp[1];
    t2 ^= kp[2];
    t3 ^= kp[3];

    kp -= 4;
    
    for(round = nr - 1; round >= 1; round --) {
        
        t4 = _saes_v2_sub_dec(t0, t3);      // SubBytes & Partial ShiftRows
        t5 = _saes_v2_sub_dec(t1, t0);
        t6 = _saes_v2_sub_dec(t2, t1);
        t7 = _saes_v2_sub_dec(t3, t2);

        t0 = _saes_v2_mix_dec(t4, t6);      // Partial ShiftRows & MixColumns
        t1 = _saes_v2_mix_dec(t5, t7);
        t2 = _saes_v2_mix_dec(t6, t4);
        t3 = _saes_v2_mix_dec(t7, t5);
    
        t0 ^= kp[0];                        // AddRoundKey
        t1 ^= kp[1];
        t2 ^= kp[2];
        t3 ^= kp[3];
    
        kp -= 4;

    }
    

    t4 = _saes_v2_sub_dec(t2, t1);          // SubBytes & Partial ShiftRows
    t5 = _saes_v2_sub_dec(t3, t2);
    t6 = _saes_v2_sub_dec(t0, t3);
    t7 = _saes_v2_sub_dec(t1, t0);
    
    t0 = (t6 & 0x0000FFFF) | (t4 & 0xFFFF0000); // Finish shift rows
    t1 = (t7 & 0x0000FFFF) | (t5 & 0xFFFF0000);
    t2 = (t4 & 0x0000FFFF) | (t6 & 0xFFFF0000);
    t3 = (t5 & 0x0000FFFF) | (t7 & 0xFFFF0000);

    t0 ^= kp[0];                            // AddRoundKey
    t1 ^= kp[1];
    t2 ^= kp[2];
    t3 ^= kp[3];

    
    U32_TO_U8_LE(pt , t0,  0);               // Write ciphertext block
    U32_TO_U8_LE(pt , t1,  4);
    U32_TO_U8_LE(pt , t2,  8);
    U32_TO_U8_LE(pt , t3, 12);
}


void    aes_128_dec_key_schedule (
    uint32_t    rk [AES_128_RK_WORDS],
    uint8_t     ck [AES_128_CK_BYTES] 
){
    aes_dec_key_schedule(rk, ck, AES_128_NK, AES_128_NR);
}

void    aes_192_dec_key_schedule (
    uint32_t    rk [AES_128_RK_WORDS],
    uint8_t     ck [AES_128_CK_BYTES] 
){
    aes_dec_key_schedule(rk, ck, AES_192_NK, AES_192_NR);
}

void    aes_256_dec_key_schedule (
    uint32_t    rk [AES_128_RK_WORDS],
    uint8_t     ck [AES_128_CK_BYTES] 
){
    aes_dec_key_schedule(rk, ck, AES_256_NK, AES_256_NR);
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
