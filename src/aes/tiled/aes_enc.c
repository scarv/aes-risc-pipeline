
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
@brief Re-arranges the bytes of each 4-word round key into quads so that
       each AddRoundKey step can be done with a simple xor.
*/
void aes_pack_key_schedule (
    uint32_t * rk,
    const int  Nr
){
    for(int i = 0; i < (Nr+1); i++) {
        uint32_t c0, c1, c2, c3;
        uint32_t q0, q1, q2, q3;

        c0 = rk[4*i+0];
        c1 = rk[4*i+1];
        c2 = rk[4*i+2];
        c3 = rk[4*i+3];

        PACK_QUAD_0(q0, c0, c1);
        PACK_QUAD_1(q1, c2, c3);
        PACK_QUAD_2(q2, c0, c1);
        PACK_QUAD_3(q3, c2, c3);
        
        rk[4*i+0] = q0;
        rk[4*i+1] = q1;
        rk[4*i+2] = q2;
        rk[4*i+3] = q3;
    
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

    uint32_t c0, c1, c2, c3;
    uint32_t q0, q1, q2, q3;
    uint32_t n0, n1, n2, n3;

    U8_TO_U32_LE(c0, pt, 0);
    U8_TO_U32_LE(c1, pt, 4);
    U8_TO_U32_LE(c2, pt, 8);
    U8_TO_U32_LE(c3, pt,12);

    PACK_QUAD_0(q0, c0, c1)
    PACK_QUAD_1(q1, c2, c3)
    PACK_QUAD_2(q2, c0, c1)
    PACK_QUAD_3(q3, c2, c3)

    q0 ^= rk[0];
    q1 ^= rk[1];
    q2 ^= rk[2];
    q3 ^= rk[3];

    for(round = 1; round < nr; round ++) {
        n0  = _saes_v5_esrsub_lo(q0, q1);
        n1  = _saes_v5_esrsub_lo(q1, q0);
        n2  = _saes_v5_esrsub_hi(q2, q3);
        n3  = _saes_v5_esrsub_hi(q3, q2);

        q0  = _saes_v5_emix(n0, n2);
        q1  = _saes_v5_emix(n1, n3);
        q2  = _saes_v5_emix(n2, n0);
        q3  = _saes_v5_emix(n3, n1);

        q0 ^= rk[4*round+0];
        q1 ^= rk[4*round+1];
        q2 ^= rk[4*round+2];
        q3 ^= rk[4*round+3];

    }
        
    n0 = _saes_v5_esrsub_lo(q0, q1);
    n1 = _saes_v5_esrsub_lo(q1, q0);
    n2 = _saes_v5_esrsub_hi(q2, q3);
    n3 = _saes_v5_esrsub_hi(q3, q2);

    q0 = n0 ^ rk[4*round+0];
    q1 = n1 ^ rk[4*round+1];
    q2 = n2 ^ rk[4*round+2];
    q3 = n3 ^ rk[4*round+3];

    UNPACK_COL_0(c0, q0, q2);
    UNPACK_COL_1(c1, q0, q2);
    UNPACK_COL_2(c2, q1, q3);
    UNPACK_COL_3(c3, q1, q3);
        
    U32_TO_U8_LE(ct, c0, 0);
    U32_TO_U8_LE(ct, c1, 4);
    U32_TO_U8_LE(ct, c2, 8);
    U32_TO_U8_LE(ct, c3,12);
}


void    aes_128_enc_key_schedule (
    uint32_t    rk [AES_128_RK_WORDS],
    uint8_t     ck [AES_128_CK_BYTES] 
){
    aes_key_schedule(rk, ck, AES_128_NK, AES_128_NR);
    aes_pack_key_schedule(rk, AES_128_NR);
}

void    aes_192_enc_key_schedule (
    uint32_t    rk [AES_128_RK_WORDS],
    uint8_t     ck [AES_128_CK_BYTES] 
){
    aes_key_schedule(rk, ck, AES_192_NK, AES_192_NR);
    aes_pack_key_schedule(rk, AES_192_NR);
}

void    aes_256_enc_key_schedule (
    uint32_t    rk [AES_128_RK_WORDS],
    uint8_t     ck [AES_128_CK_BYTES] 
){
    aes_key_schedule(rk, ck, AES_256_NK, AES_256_NR);
    aes_pack_key_schedule(rk, AES_256_NR);
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
