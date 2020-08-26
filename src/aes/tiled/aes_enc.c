
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
            temp  = _saes_v5_sub(temp);
            temp ^= round_const[i/Nk];

        } else if ( (Nk > 6) && (i % Nk == 4)) {
            
            temp  = _saes_v5_sub(temp);

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

//!@}
