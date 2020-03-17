
/*!
@addtogroup crypto_block_aes_zscrypto_tiled Tiled AES Proposal 
@brief Implementation of AES Using the tiled instruction proposals..
@ingroup crypto_block_aes
@{
*/

#include "aes.h"
#include "intrinsics.h"
#include "tiled_common.h"

//! AES Round constants
static const uint8_t round_const[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 
};


/*!
@brief A generic AES key schedule
*/
void    aes_key_schedule (
    uint32_t * rk , //!< Output Nk*(Nr+1) word cipher key.
    uint8_t  * ck , //!< Input Nk byte cipher key
    const int  Nk , //!< Number of words in the key.
    const int  Nr   //!< Number of rounds.
){
    const int        Nb = 4;

    for(int i = 0; i < Nb; i ++) {
        U8_TO_U32_LE(rk[i], ck,  4*i);
    }
    
    for(int i = 4; i < Nk*(Nr+1); i += 1) {

        uint32_t temp = rk[i-1];

        if( i % Nk == 0 ) {

            temp  = ROTR32(temp, 8);
            temp  = _saes_v1_encs(temp);
            temp ^= round_const[i/Nk];

        } else if ( (Nk > 6) && (i % Nk == 4)) {
            
            temp  = _saes_v1_encs(temp);

        }

        rk[i] = rk[i-Nk] ^ temp;
    }
}


/*!
*/
void    aes_enc_block (
    uint8_t     ct [16],
    uint8_t     pt [16],
    uint32_t  * rk,
    int         nr
){
    int round = 0;

    uint32_t n0, n1, n2, n3;
    uint32_t t0, t1, t2, t3;

    U8_TO_U32_LE(t0, pt, 0);
    U8_TO_U32_LE(t1, pt, 4);
    U8_TO_U32_LE(t2, pt, 8);
    U8_TO_U32_LE(t3, pt,12);

    t0 ^= rk[0];
    t1 ^= rk[1];
    t2 ^= rk[2];
    t3 ^= rk[3];

    for(round = 1; round < nr; round ++) {
        
        //
        // Sub Bytes
        t0 = _saes_v1_encs(t0);
        t1 = _saes_v1_encs(t1);
        t2 = _saes_v1_encs(t2);
        t3 = _saes_v1_encs(t3);

        //
        // Shift Rows
        n0 = (t0 & 0x000000FF) | (t1 & 0x0000FF00) |
             (t2 & 0x00FF0000) | (t3 & 0xFF000000) ;
        
        n1 = (t1 & 0x000000FF) | (t2 & 0x0000FF00) | 
             (t3 & 0x00FF0000) | (t0 & 0xFF000000) ;
        
        n2 = (t2 & 0x000000FF) | (t3 & 0x0000FF00) |
             (t0 & 0x00FF0000) | (t1 & 0xFF000000) ;

        n3 = (t3 & 0x000000FF) | (t0 & 0x0000FF00) |
             (t1 & 0x00FF0000) | (t2 & 0xFF000000) ;

        //
        // Mix Columns

        t0 = _saes_v1_encm(n0);
        t1 = _saes_v1_encm(n1);
        t2 = _saes_v1_encm(n2);
        t3 = _saes_v1_encm(n3);
        
        //
        // Add Round Key

        t0 ^= rk[4*round + 0];
        t1 ^= rk[4*round + 1];
        t2 ^= rk[4*round + 2];
        t3 ^= rk[4*round + 3];
    }
    //
    // Sub Bytes
    t0 = _saes_v1_encs(t0);
    t1 = _saes_v1_encs(t1);
    t2 = _saes_v1_encs(t2);
    t3 = _saes_v1_encs(t3);

    //
    // Shift Rows
    n0 = (t0 & 0x000000FF) | (t1 & 0x0000FF00) |
         (t2 & 0x00FF0000) | (t3 & 0xFF000000) ;
    
    n1 = (t1 & 0x000000FF) | (t2 & 0x0000FF00) | 
         (t3 & 0x00FF0000) | (t0 & 0xFF000000) ;
    
    n2 = (t2 & 0x000000FF) | (t3 & 0x0000FF00) |
         (t0 & 0x00FF0000) | (t1 & 0xFF000000) ;

    n3 = (t3 & 0x000000FF) | (t0 & 0x0000FF00) |
         (t1 & 0x00FF0000) | (t2 & 0xFF000000) ;

    
    //
    // Add Round Key

    t0 = n0 ^ rk[4*round + 0];
    t1 = n1 ^ rk[4*round + 1];
    t2 = n2 ^ rk[4*round + 2];
    t3 = n3 ^ rk[4*round + 3];
        
    U32_TO_U8_LE(ct, t0, 0);
    U32_TO_U8_LE(ct, t1, 4);
    U32_TO_U8_LE(ct, t2, 8);
    U32_TO_U8_LE(ct, t3,12);
}


void    aes_128_enc_key_schedule (
    uint32_t    rk [AES_128_RK_WORDS],
    uint8_t     ck [AES_128_CK_BYTES] 
){
    aes_key_schedule(rk, ck, AES_128_NK, AES_128_NR);
}

void    aes_192_enc_key_schedule (
    uint32_t    rk [AES_128_RK_WORDS],
    uint8_t     ck [AES_128_CK_BYTES] 
){
    aes_key_schedule(rk, ck, AES_192_NK, AES_192_NR);
}

void    aes_256_enc_key_schedule (
    uint32_t    rk [AES_128_RK_WORDS],
    uint8_t     ck [AES_128_CK_BYTES] 
){
    aes_key_schedule(rk, ck, AES_256_NK, AES_256_NR);
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
