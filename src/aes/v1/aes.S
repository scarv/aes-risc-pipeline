
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



.func   aes_enc_block                           // a0 - uint8_t     ct [16],
.global aes_enc_block                           // a1 - uint8_t     pt [16],
aes_enc_block:                                  // a2 - uint32_t  * rk,
                                                // a3 - int         nr
    #define T0 a4
    #define T1 a5
    #define T2 a6
    #define T3 a7
    #define U0 t0
    #define U1 t1
    #define U2 t2
    #define U3 t3
    #define TMP t4
    #define HM t5
    #define MSK t6
    #define CT a0
    #define PT a1
    #define RK a2
    #define NR a3
    #define KP a3

    slli    KP, NR, 4
    add     KP, KP, RK                          // kp = rk + 4*nr

    AES_LOAD_STATE T0,T1,T2,T3,PT,U0,U1,U2,U3   // Columns in T*

    lw      U0,  0(RK)                          // Load Round Key
    lw      U1,  4(RK)
    lw      U2,  8(RK)
    lw      U3, 12(RK)

    xor     T0, T0, U0                          // Add Round Key
    xor     T1, T1, U1
    xor     T2, T2, U2
    xor     T3, T3, U3

    addi    RK, RK, 16                          // Move to next round key.

    li      MSK, 0xFF
    
.aes_enc_block_l0:
    
        saes.v1.encs U0, T0                     // SubBytes
        saes.v1.encs U1, T1                     //
        saes.v1.encs U2, T2                     //
        saes.v1.encs U3, T3                     //

        AES_SHIFT_ROWS T0, T1, T2, T3, U0, U1, U2, U3, TMP, HM, MSK
        
        saes.v1.encm T0, T0                     // MixColumns
        saes.v1.encm T1, T1                     //
        saes.v1.encm T2, T2                     //
        saes.v1.encm T3, T3                     //

        lw      U0,  0(RK)                      // Load Round Key
        lw      U1,  4(RK)
        lw      U2,  8(RK)
        lw      U3, 12(RK)

        xor     T0, T0, U0                      // Add Round Key
        xor     T1, T1, U1                      //
        xor     T2, T2, U2                      //
        xor     T3, T3, U3                      //
    
        addi    RK, RK, 16                      // Move to next round key.

    bne RK, KP, .aes_enc_block_l0               // Repeat loop

.aes_enc_block_l_finish:

    saes.v1.encs U0, T0                         // SubBytes
    saes.v1.encs U1, T1                         //
    saes.v1.encs U2, T2                         //
    saes.v1.encs U3, T3                         //

    AES_SHIFT_ROWS T0, T1, T2, T3, U0, U1, U2, U3, TMP, HM, MSK

    lw      U0,  0(RK)                          // Load Round Key
    lw      U1,  4(RK)
    lw      U2,  8(RK)
    lw      U3, 12(RK)

    xor     T0, T0, U0                          // Add Round Key
    xor     T1, T1, U1                          //
    xor     T2, T2, U2                          //
    xor     T3, T3, U3                          //

.aes_enc_block_end:

    AES_DUMP_STATE  T0, T1, T2, T3, CT

    ret
    
    #undef T0 
    #undef T1 
    #undef T2 
    #undef T3 
    #undef U0 
    #undef U1 
    #undef U2 
    #undef U3 
    #undef TMP
    #undef HM 
    #undef MSK
    #undef CT 
    #undef PT 
    #undef RK 
    #undef NR 
    #undef KP 

.endfunc

.func   aes_dec_block                           // a0 - uint8_t     pt [16],
.global aes_dec_block                           // a1 - uint8_t     ct [16],
aes_dec_block:                                  // a2 - uint32_t  * rk,
                                                // a3 - int         nr
    #define T0 a4
    #define T1 a5
    #define T2 a6
    #define T3 a7
    #define U0 t0
    #define U1 t1
    #define U2 t2
    #define U3 t3
    #define TMP t4
    #define HM t5
    #define MSK t6
    #define PT a0
    #define CT a1
    #define RK a2
    #define NR a3
    #define KP a3

    slli    KP, NR, 4
    add     KP, KP, RK                          // kp = rk + 4*nr

    AES_LOAD_STATE T0,T1,T2,T3,CT,U0,U1,U2,U3   // Columns in T*

    lw      U0,  0(KP)                          // Load Round Key
    lw      U1,  4(KP)
    lw      U2,  8(KP)
    lw      U3, 12(KP)

    xor     T0, T0, U0                          // Add Round Key
    xor     T1, T1, U1
    xor     T2, T2, U2
    xor     T3, T3, U3
    
    addi    KP, KP, -16
    
    li      MSK, 0xFF

    .aes_dec_block_l0:

        AES_INV_SHIFT_ROWS U0, U1, U2, U3, T0, T1, T2, T3, TMP, HM, MSK

        saes.v1.decs T0, U0
        saes.v1.decs T1, U1
        saes.v1.decs T2, U2
        saes.v1.decs T3, U3
    
        lw      U0,  0(KP)                      // Load Round Key
        lw      U1,  4(KP)
        lw      U2,  8(KP)
        lw      U3, 12(KP)

        xor     T0, T0, U0                      // Add Round Key
        xor     T1, T1, U1
        xor     T2, T2, U2
        xor     T3, T3, U3
        
        saes.v1.decm T0, T0
        saes.v1.decm T1, T1
        saes.v1.decm T2, T2
        saes.v1.decm T3, T3

        addi    KP, KP, -16

        bne KP, RK, .aes_dec_block_l0
    
    AES_INV_SHIFT_ROWS U0, U1, U2, U3, T0, T1, T2, T3, TMP, HM, MSK
        
    saes.v1.decs T0, U0
    saes.v1.decs T1, U1
    saes.v1.decs T2, U2
    saes.v1.decs T3, U3
        
    lw      U0,  0(KP)                      // Load Round Key
    lw      U1,  4(KP)
    lw      U2,  8(KP)
    lw      U3, 12(KP)

    xor     T0, T0, U0                      // Add Round Key
    xor     T1, T1, U1
    xor     T2, T2, U2
    xor     T3, T3, U3

    
    AES_DUMP_STATE T0,T1,T2,T3,PT   // Columns in T*

    ret
    
    #undef T0 
    #undef T1 
    #undef T2 
    #undef T3 
    #undef U0 
    #undef U1 
    #undef U2 
    #undef U3 
    #undef TMP
    #undef HM 
    #undef MSK
    #undef CT 
    #undef PT 
    #undef RK 
    #undef NR 
    #undef KP 

.endfunc


