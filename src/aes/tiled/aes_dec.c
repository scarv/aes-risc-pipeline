
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


void    aes_128_dec_key_schedule (
    uint32_t    rk [AES_128_RK_WORDS],
    uint8_t     ck [AES_128_CK_BYTES] 
){
    aes_128_enc_key_schedule(rk, ck);
}

//!@}

