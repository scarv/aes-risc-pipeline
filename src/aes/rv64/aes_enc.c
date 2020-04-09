

#include "aes.h"
#include "intrinsics.h"

//! AES Round constants
static const uint8_t round_const[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 
};

//  Encrypt rounds. Implements AES-128/192/256 depending on nr = {10,12,14}
void aes_enc_block (
    uint8_t   ct[16],
    uint8_t   pt[16],
    uint32_t *rk,
    int nr
) {
    uint64_t   n0, n1               ;
    int        rnd = 0              ;

    uint64_t * ptp = (uint64_t*)pt   ;
    uint64_t * ctp = (uint64_t*)ct   ;
    uint64_t * rkp = (uint64_t*)rk   ;

    uint64_t   t0  = ptp[0]         ;
    uint64_t   t1  = ptp[1]         ;

               n0  = t0 ^ rkp[0]    ;
               n1  = t1 ^ rkp[1]    ;

              rkp += 2              ;

    for(rnd = 1; rnd < nr; rnd ++) {
        
        t0  = _saes_v4_encsm_lo(n0, n1);
        t1  = _saes_v4_encsm_hi(n0, n1);
        n0  = t0 ^ rkp[0];
        n1  = t1 ^ rkp[1];
        rkp+= 2;
    }

    t0  = _saes_v4_encs_lo(n0, n1);
    t1  = _saes_v4_encs_hi(n0, n1);
    t0 ^= rkp[0];
    t1 ^= rkp[1];

    ctp[0] = t0;
    ctp[1] = t1;
}


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


void    aes_128_enc_key_schedule (
    uint32_t    rk [AES_128_RK_WORDS],
    uint8_t     ck [AES_128_CK_BYTES] 
) {
    uint64_t   temp     ;

    uint64_t * rkp      = (uint64_t*)rk ;
    uint64_t * ckp      = (uint64_t*)ck ;

    uint64_t   rk_lo    = ckp[0];
    uint64_t   rk_hi    = ckp[1];

    rkp[0]              = rk_lo;
    rkp[1]              = rk_hi;
    rkp                += 2    ;

    #define AES_128_KS_STEP(RCON) { \
        temp                = _saes_v4_ks1(rk_hi, RCON ); \
        rk_lo               = _saes_v4_ks2(temp , rk_lo); \
        rk_hi               = _saes_v4_ks2(rk_lo, rk_hi); \
        rkp[0]              = rk_lo; \
        rkp[1]              = rk_hi; \
        rkp                += 2    ; \
    }

    
    AES_128_KS_STEP( 0)
    AES_128_KS_STEP( 1)
    AES_128_KS_STEP( 2)
    AES_128_KS_STEP( 3)
    AES_128_KS_STEP( 4)
    AES_128_KS_STEP( 5)
    AES_128_KS_STEP( 6)
    AES_128_KS_STEP( 7)
    AES_128_KS_STEP( 8)
    AES_128_KS_STEP( 9)
    AES_128_KS_STEP(10)
    
    #undef AES_128_KS_STEP
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
