
#include "aes_common.S"

.data

//
// Round constants for the AES Key Schedule
aes_round_const:
    .byte 0x01
    .byte 0x02
    .byte 0x04
    .byte 0x08
    .byte 0x10
    .byte 0x20
    .byte 0x40
    .byte 0x80
    .byte 0x1b
    .byte 0x36 

.text

.func     aes_128_enc_key_schedule
.global   aes_128_enc_key_schedule
aes_128_enc_key_schedule:       // a0 - uint32_t rk [AES_128_RK_WORDS]
                                // a1 - uint8_t  ck [AES_128_CK_BYTE

    #define C0  a2
    #define C1  a3
    #define C2  a4
    #define C3  a5
    #define RK  a0
    #define CK  a1
    #define RKE t0
    #define RCP t1
    #define RCT t2
    #define T1  t3
    #define T2  t4

    AES_LOAD_STATE C0,C1,C2,C3,CK,t0,t1,t2,t3 

    addi    RKE, RK, 160        // t0 = rke = rk + 40
    la      RCP, aes_round_const// t1 = round constant pointer

.aes_128_enc_ks_l0:

    sw      C0,  0(RK)          // rkp[0] = a2
    sw      C1,  4(RK)          // rkp[1] = a3
    sw      C2,  8(RK)          // rkp[2] = a4
    sw      C3, 12(RK)          // rkp[3] = a5
                                
                                // if rke==rkp, return - loop break
    beq     RKE, RK, .aes_128_enc_ks_finish

    addi    RK, RK, 16          // increment rkp

    lbu     RCT, 0(RCP)         // Load round constant byte
    addi    RCP, RCP, 1         // Increment round constant byte
    xor     C0, C0, RCT         // c0 ^= rcp

    ROR32I T1, T2, C3, 8        // tr = ROR32(c3, 8)
    saes.v1.encs T1, T1         // tr = sbox(tr)

    xor     C0, C0, T1          // C0 ^= tr
    xor     C1, C1, C0          // C1 ^= C0
    xor     C2, C2, C1          // C1 ^= C0
    xor     C3, C3, C2          // C1 ^= C0

    j .aes_128_enc_ks_l0        // Loop continue

.aes_128_enc_ks_finish:
    ret

    #undef C0 
    #undef C1 
    #undef C2 
    #undef C3 
    #undef RK 
    #undef CK 
    #undef RKE
    #undef RCP
    #undef RCT
    #undef T1 
    #undef T2 

.endfunc

