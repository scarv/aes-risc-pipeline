
/*!
@addtogroup crypto_block_aes_zscrypto_v1 AES Proposal 1 
@brief Implementation of AES Using the v1 instruction proposals.
@ingroup crypto_block_aes
@{
*/

#include "aes.h"
#include "intrinsics.h"
#include "v1_common.h"

void    aes_128_dec_key_schedule (
    uint32_t    rk [AES_128_RK_WORDS],
    uint8_t     ck [AES_128_CK_BYTES] 
){
    aes_128_enc_key_schedule(rk, ck);
}


//!@}

