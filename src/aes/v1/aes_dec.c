
/*!
@addtogroup crypto_block_aes_zscrypto_v1 AES Proposal 1 
@brief Implementation of AES Using the v1 instruction proposals.
@ingroup crypto_block_aes
@{
*/

#include "aes.h"
#include "intrinsics.h"
#include "v1_common.h"


// Defined in aes_enc.c
extern void    aes_key_schedule (
    uint32_t * rk , //!< Output Nk*(Nr+1) word cipher key.
    uint8_t  * ck , //!< Input Nk byte cipher key
    const int  Nk , //!< Number of words in the key.
    const int  Nr   //!< Number of rounds.
);

/*
 * Commented out since we are now using the mix columns instruction.
//! Inverse mix columns transformation.
static uint32_t aes_mix_column_dec(
    uint32_t col
){
    uint8_t b0,b1,b2,b3;
    uint8_t s0,s1,s2,s3;
    
    s0 = (col >>  0) & 0xFF;
    s1 = (col >>  8) & 0xFF;
    s2 = (col >> 16) & 0xFF;
    s3 = (col >> 24) & 0xFF;

    b0 = XTE(s0) ^ XTB(s1) ^ XTD(s2) ^ XT9(s3);
    b1 = XT9(s0) ^ XTE(s1) ^ XTB(s2) ^ XTD(s3);
    b2 = XTD(s0) ^ XT9(s1) ^ XTE(s2) ^ XTB(s3);
    b3 = XTB(s0) ^ XTD(s1) ^ XT9(s2) ^ XTE(s3);

    uint32_t tr = 
        (((uint32_t)b3) << 24) |
        (((uint32_t)b2) << 16) |
        (((uint32_t)b1) <<  8) |
        (((uint32_t)b0) <<  0) ;

    return tr;
}
*/


/*!
@brief Generic single-block AES encrypt function
@param [out] pt - Output plaintext
@param [in]  ct - Input cipher text
@param [in]  rk - The expanded key schedule
@param [in]  nr - Number of decryption rounds to perform.
*/
void    aes_dec_block (
    uint8_t     pt [16],
    uint8_t     ct [16],
    uint32_t  * rk,
    int         nr
){
    
    int      round;
    uint32_t n0, n1, n2, n3;
    uint32_t t0, t1, t2, t3;

    U8_TO_U32_LE(t0, ct,  0) 
    U8_TO_U32_LE(t1, ct,  4) 
    U8_TO_U32_LE(t2, ct,  8) 
    U8_TO_U32_LE(t3, ct, 12) 

    t0 ^= rk[4*nr + 0];
    t1 ^= rk[4*nr + 1];
    t2 ^= rk[4*nr + 2];
    t3 ^= rk[4*nr + 3];

    for(round = nr-1; round >= 1; round --) {

        //
        // Inv ShiftRows
        
        n0 = (t0 & 0x000000FF) | (t3 & 0x0000FF00) |
             (t2 & 0x00FF0000) | (t1 & 0xFF000000) ;
        
        n1 = (t1 & 0x000000FF) | (t0 & 0x0000FF00) | 
             (t3 & 0x00FF0000) | (t2 & 0xFF000000) ;
        
        n2 = (t2 & 0x000000FF) | (t1 & 0x0000FF00) |
             (t0 & 0x00FF0000) | (t3 & 0xFF000000) ;

        n3 = (t3 & 0x000000FF) | (t2 & 0x0000FF00) |
             (t1 & 0x00FF0000) | (t0 & 0xFF000000) ;

        //
        // Inv SubBytes

        t0 = _saes_v1_decs(n0);
        t1 = _saes_v1_decs(n1);
        t2 = _saes_v1_decs(n2);
        t3 = _saes_v1_decs(n3);

        //
        // Add Round Key

        t0 ^= rk[4*round + 0];
        t1 ^= rk[4*round + 1];
        t2 ^= rk[4*round + 2];
        t3 ^= rk[4*round + 3];

        //
        // Inv MixColumns

        t0 = _saes_v1_decm(t0);
        t1 = _saes_v1_decm(t1);
        t2 = _saes_v1_decm(t2);
        t3 = _saes_v1_decm(t3);

    }

    //
    // Inv ShiftRows
    
    n0 = (t0 & 0x000000FF) | (t3 & 0x0000FF00) |
         (t2 & 0x00FF0000) | (t1 & 0xFF000000) ;
    
    n1 = (t1 & 0x000000FF) | (t0 & 0x0000FF00) | 
         (t3 & 0x00FF0000) | (t2 & 0xFF000000) ;
    
    n2 = (t2 & 0x000000FF) | (t1 & 0x0000FF00) |
         (t0 & 0x00FF0000) | (t3 & 0xFF000000) ;

    n3 = (t3 & 0x000000FF) | (t2 & 0x0000FF00) |
         (t1 & 0x00FF0000) | (t0 & 0xFF000000) ;

    //
    // Inv SubBytes

    t0 = _saes_v1_decs(n0);
    t1 = _saes_v1_decs(n1);
    t2 = _saes_v1_decs(n2);
    t3 = _saes_v1_decs(n3);

    //
    // Add Round Key

    t0 ^= rk[4*round + 0];
    t1 ^= rk[4*round + 1];
    t2 ^= rk[4*round + 2];
    t3 ^= rk[4*round + 3];
    
    U32_TO_U8_LE(pt, t0, 0);
    U32_TO_U8_LE(pt, t1, 4);
    U32_TO_U8_LE(pt, t2, 8);
    U32_TO_U8_LE(pt, t3,12);
}

void    aes_128_dec_key_schedule (
    uint32_t    rk [AES_128_RK_WORDS],
    uint8_t     ck [AES_128_CK_BYTES] 
){
    aes_key_schedule(rk, ck, AES_128_NK, AES_128_NR);
}

void    aes_192_dec_key_schedule (
    uint32_t    rk [AES_128_RK_WORDS],
    uint8_t     ck [AES_128_CK_BYTES] 
){
    aes_key_schedule(rk, ck, AES_192_NK, AES_192_NR);
}

void    aes_256_dec_key_schedule (
    uint32_t    rk [AES_128_RK_WORDS],
    uint8_t     ck [AES_128_CK_BYTES] 
){
    aes_key_schedule(rk, ck, AES_256_NK, AES_256_NR);
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

