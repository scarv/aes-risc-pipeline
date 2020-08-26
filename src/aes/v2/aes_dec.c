
/*!
@addtogroup crypto_block_aes_zscrypto_v2 AES ZSCrypto V2
@ingroup crypto_block_aes
@{
*/

#include "aes.h"
#include "intrinsics.h"


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

//!@}
