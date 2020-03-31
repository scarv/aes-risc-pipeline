
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

.extern AES_ENC_TBOX_4

.text

.func     aes_128_enc_key_schedule
.global   aes_128_enc_key_schedule
aes_128_enc_key_schedule:       // a0 - uint32_t rk [AES_128_RK_WORDS]
                                // a1 - uint8_t  ck [AES_128_CK_BYTE

    #define C0  a2
    #define C1  a3
    #define C2  a4
    #define C3  a5
    #define TT  a6
    #define MM  a7

    #define RK  a0
    #define CK  a1

    #define RKE t0
    #define RCP t1
    #define RCT t2

    #define T0  t3
    #define T1  t4
    #define T2  t5
    #define T3  t6

    AES_LOAD_STATE C0,C1,C2,C3,CK,t0,t1,t2,t3 

    addi    RKE, RK, 160        // t0 = rke = rk + 40
    la      RCP, aes_round_const// t1 = round constant pointer
    la      TT , AES_ENC_TBOX_4

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
    
    li      MM, 0xFF

    srli    T0, C3, 6
    srli    T1, C3, 14
    srli    T2, C3, 22
    
    andi    T0, T0, 0xFF<<2
    andi    T1, T1, 0xFF<<2
    andi    T2, T2, 0xFF<<2
    andi    T3, C3, 0xFF

    slli    T3, T3, 2

    add     T0, T0, TT          // T* = &AES_ENC_TBOX_4[(C0 >> 0) & 0xFF]
    add     T1, T1, TT
    add     T2, T2, TT
    add     T3, T3, TT

    lw      T0, 0(T0)           // T* = &AES_ENC_TBOX_4[(C0 >> 0) & 0xFF]
    lw      T1, 0(T1)
    lw      T2, 0(T2)
    lw      T3, 0(T3)

    and     T0, T0, MM
    slli    MM, MM, 8
    and     T1, T1, MM
    slli    MM, MM, 8
    and     T2, T2, MM
    slli    MM, MM, 8
    and     T3, T3, MM

    xor     T0, T0, T1
    xor     T0, T0, T2
    xor     T0, T0, T3
    xor     C0, C0, T0
    xor     C0, C0, RCT         // c0 ^= rcp

    // Load Rotated/sboxed value into c0

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
