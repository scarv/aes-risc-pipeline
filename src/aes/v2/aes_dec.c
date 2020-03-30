
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
extern void    aes_dec_block(
    uint8_t     pt [16],
    uint8_t     ct [16],
    uint32_t  * rk,
    int         nr
);


void    aes_128_dec_key_schedule (
    uint32_t    rk [AES_128_RK_WORDS],
    uint8_t     ck [AES_128_CK_BYTES] 
){
    aes_128_enc_key_schedule(rk, ck);
    
    for(int i = 1; i < AES_128_NR; i ++) {
        
        uint32_t* t = rk  +  (4*i);

        t[0] = _saes_v2_mix_dec(t[0],t[0]);
        t[1] = _saes_v2_mix_dec(t[1],t[1]);
        t[2] = _saes_v2_mix_dec(t[2],t[2]);
        t[3] = _saes_v2_mix_dec(t[3],t[3]);

    }
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
