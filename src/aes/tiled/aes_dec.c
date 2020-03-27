
/*!
@addtogroup crypto_block_aes_zscrypto_tiled Tiled AES Proposal 
@brief Implementation of AES Using the tiled instruction proposals.
@ingroup crypto_block_aes
@{
*/

#include "aes.h"
#include "intrinsics.h"
#include "tiled_common.h"


// Defined in aes_enc.c
extern void    aes_key_schedule (
    uint32_t * rk , //!< Output Nk*(Nr+1) word cipher key.
    uint8_t  * ck , //!< Input Nk byte cipher key
    const int  Nk , //!< Number of words in the key.
    const int  Nr   //!< Number of rounds.
);


// Defined in aes/tiled/aes_enc.c
extern void aes_pack_key_schedule (
    uint32_t * rk,
    const int  Nr
);


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
    uint32_t c0, c1, c2, c3;
    uint32_t q0, q1, q2, q3;
    uint32_t n0, n1, n2, n3;

    AES_LOAD_STATE(c0,c1,c2,c3,ct);
    
    PACK_QUAD_0(q0, c0, c1)
    PACK_QUAD_1(q1, c2, c3)
    PACK_QUAD_2(q2, c0, c1)
    PACK_QUAD_3(q3, c2, c3)

    q0 ^= rk[4*nr + 0];
    q1 ^= rk[4*nr + 1];
    q2 ^= rk[4*nr + 2];
    q3 ^= rk[4*nr + 3];
        
    n0  = _saes_v5_dsrsub_lo(q0, q1);
    n1  = _saes_v5_dsrsub_lo(q1, q0);
    n2  = _saes_v5_dsrsub_hi(q2, q3);
    n3  = _saes_v5_dsrsub_hi(q3, q2);

    for(round = nr-1; round >= 1; round --) {
        
        n0 ^= rk[4*round+0];
        n1 ^= rk[4*round+1];
        n2 ^= rk[4*round+2];
        n3 ^= rk[4*round+3];

        q0  = _saes_v5_dmix(n0, n2);
        q1  = _saes_v5_dmix(n1, n3);
        q2  = _saes_v5_dmix(n2, n0);
        q3  = _saes_v5_dmix(n3, n1);
        
        n0  = _saes_v5_dsrsub_lo(q0, q1);
        n1  = _saes_v5_dsrsub_lo(q1, q0);
        n2  = _saes_v5_dsrsub_hi(q2, q3);
        n3  = _saes_v5_dsrsub_hi(q3, q2);

    }
        
    n0 ^= rk[0];
    n1 ^= rk[1];
    n2 ^= rk[2];
    n3 ^= rk[3];
    
    UNPACK_COL_0(c0, n0, n2);
    UNPACK_COL_1(c1, n0, n2);
    UNPACK_COL_2(c2, n1, n3);
    UNPACK_COL_3(c3, n1, n3);

    
    U32_TO_U8_LE(pt, c0, 0);
    U32_TO_U8_LE(pt, c1, 4);
    U32_TO_U8_LE(pt, c2, 8);
    U32_TO_U8_LE(pt, c3,12);
}

void    aes_128_dec_key_schedule (
    uint32_t    rk [AES_128_RK_WORDS],
    uint8_t     ck [AES_128_CK_BYTES] 
){
    aes_key_schedule(rk, ck, AES_128_NK, AES_128_NR);
    aes_pack_key_schedule(rk, AES_128_NR);
}

void    aes_192_dec_key_schedule (
    uint32_t    rk [AES_128_RK_WORDS],
    uint8_t     ck [AES_128_CK_BYTES] 
){
    aes_key_schedule(rk, ck, AES_192_NK, AES_192_NR);
    aes_pack_key_schedule(rk, AES_192_NR);
}

void    aes_256_dec_key_schedule (
    uint32_t    rk [AES_128_RK_WORDS],
    uint8_t     ck [AES_128_CK_BYTES] 
){
    aes_key_schedule(rk, ck, AES_256_NK, AES_256_NR);
    aes_pack_key_schedule(rk, AES_256_NR);
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

