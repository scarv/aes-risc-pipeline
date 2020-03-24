
#include "aes.h"
#include "intrinsics.h"

extern void    aes_key_schedule (
    uint32_t * rk , //!< Output Nk*(Nr+1) word cipher key.
    uint8_t  * ck , //!< Input Nk byte cipher key
    const int  Nk , //!< Number of words in the key.
    const int  Nr   //!< Number of rounds.
);


//  Decrypt rounds. Implements AES-128/192/256 depending on nr = {10,12,14}
void aes_dec_block (
    uint8_t    pt[16],
    uint8_t    ct[16],
    uint32_t * rk,
    int nr
) {
    uint64_t   n0, n1               ;
    int        rnd = 0              ;

    uint64_t * ptp = (uint64_t*)pt   ;
    uint64_t * ctp = (uint64_t*)ct   ;
    uint64_t * rkp = (uint64_t*)rk + (nr*2);

    uint64_t   t0  = ctp[0]         ;
    uint64_t   t1  = ctp[1]         ;

               n0  = t0 ^ rkp[0]    ;
               n1  = t1 ^ rkp[1]    ;

              rkp -= 2              ;

    for(rnd = nr-1; rnd > 0; rnd --) {

        t0  = _saes_v4_decsm_lo(n0, n1);
        t1  = _saes_v4_decsm_hi(n0, n1);
               
        n0  = t0 ^ rkp[0]    ;
        n1  = t1 ^ rkp[1]    ;

        rkp-= 2              ;

    }
    
    t0  = _saes_v4_decs_lo(n0, n1);
    t1  = _saes_v4_decs_hi(n0, n1);
    t0 ^= rkp[0];
    t1 ^= rkp[1];

    ptp[0] = t0;
    ptp[1] = t1;
}


void    aes_dec_key_schedule (
    uint32_t    rk [16],
    uint8_t     ck [16],
    const int  Nk , //!< Number of words in the key.
    const int  Nr   //!< Number of rounds.
){
    aes_key_schedule(rk, ck, Nk, Nr);

    for(int i = 1; i < Nr; i ++) {
        
        uint32_t* t = rk  +  (4*i);

        t[0] = _saes_v2_mix_dec(t[0],t[0]);
        t[1] = _saes_v2_mix_dec(t[1],t[1]);
        t[2] = _saes_v2_mix_dec(t[2],t[2]);
        t[3] = _saes_v2_mix_dec(t[3],t[3]);

    }
}


void    aes_128_dec_key_schedule (
    uint32_t    rk [AES_128_RK_WORDS],
    uint8_t     ck [AES_128_CK_BYTES] 
){
    aes_dec_key_schedule(rk, ck, AES_128_NK, AES_128_NR);
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
