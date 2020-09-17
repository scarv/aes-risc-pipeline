
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

.extern AES_ENC_TBOX_0
.extern AES_ENC_TBOX_1
.extern AES_ENC_TBOX_2
.extern AES_ENC_TBOX_3
.extern AES_ENC_TBOX_4

.extern AES_DEC_TBOX_0
.extern AES_DEC_TBOX_1
.extern AES_DEC_TBOX_2
.extern AES_DEC_TBOX_3
.extern AES_DEC_TBOX_4

.text

.func     aes_128_enc_key_schedule
.global   aes_128_enc_key_schedule
aes_128_enc_key_schedule:       // a0 - uint32_t rk [AES_128_RK_WORDS]
                                // a1 - uint8_t  ck [AES_128_CK_BYTE]

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
    #undef T0
    #undef T1
    #undef T2
    #undef T3

.endfunc


.func     aes_128_dec_key_schedule
.global   aes_128_dec_key_schedule
aes_128_dec_key_schedule:       // a0 - uint32_t rk [AES_128_RK_WORDS]
                                // a1 - uint8_t  ck [AES_128_CK_BYTE]

    #define RKP      s0
    #define LOOP_END t6
    #define TB0      a2
    #define TB1      a3
    #define TB2      a4
    #define TB3      a5
    #define TB4      a6

    addi    sp, sp, -16
    sw      RKP, 0(sp)
    sw      ra , 4(sp)

    mv   RKP, a0                // Save a0 since call destroys it

    call aes_128_enc_key_schedule

    addi LOOP_END, RKP, 160
    addi RKP     , RKP, 16

    la     TB4, AES_ENC_TBOX_4
    la     TB0, AES_DEC_TBOX_0
    la     TB1, AES_DEC_TBOX_1
    la     TB2, AES_DEC_TBOX_2
    la     TB3, AES_DEC_TBOX_3

.aes_128_dec_ks_l0:
    lw      t0, 0(RKP)
    
    andi    t1, t0, 0xFF

    slli    t1, t1, 2           // Word align LS byte of t0
    srli    t2, t0, 6
    srli    t3, t0, 14
    srli    t4, t0, 22
    andi    t2, t2, 0xFF << 2   // Word align bytes of t0
    andi    t3, t3, 0xFF << 2
    andi    t4, t4, 0xFF << 2

    add     t1, t1, TB4         // Add to base adress of AES_ENC_TBOX_4
    add     t2, t2, TB4
    add     t3, t3, TB4
    add     t4, t4, TB4

    lbu     t1, 0(t1)           // Load entries for AES_ENC_TBOX_4
    lbu     t2, 0(t2)
    lbu     t3, 0(t3)
    lbu     t4, 0(t4)

    slli    t1, t1, 2           // Masked and aligned outputs from
    slli    t2, t2, 2           // AES_ENC_TBOX_4
    slli    t3, t3, 2
    slli    t4, t4, 2

    add     t1, t1, TB0         // Add to TBOX base addresses
    add     t2, t2, TB1
    add     t3, t3, TB2
    add     t4, t4, TB3

    lw      t1, 0(t1)           // Load from TBoxes
    lw      t2, 0(t2)
    lw      t3, 0(t3)
    lw      t4, 0(t4)

    xor     t0, t1, t2          // Accumulate
    xor     t0, t0, t3
    xor     t0, t0, t4
    
    sw      t0, 0(RKP)

    addi    RKP, RKP, 4         // Increment round key pointer.
    bne     RKP, LOOP_END, .aes_128_dec_ks_l0

    lw      RKP, 0(sp)
    lw      ra , 4(sp)
    addi    sp, sp, 16

    ret
.endfunc


.macro T_ENC_LOOKUP_RND T0, T1, T2, T3, RK, U0, U1, U2, U3, A0, A1, A2, A3, S0, S1, S2, S3, TX, TY, TZ
    andi    \A0, \T0, 0xFF
    andi    \A1, \T1, 0xFF
    andi    \A2, \T2, 0xFF
    andi    \A3, \T3, 0xFF
    slli    \A0, \A0, 2
    slli    \A1, \A1, 2
    slli    \A2, \A2, 2
    slli    \A3, \A3, 2
    add     \A0, \A0, \U0               // A* = TBOX_0 + (t* >> 0)
    add     \A1, \A1, \U0
    add     \A2, \A2, \U0
    add     \A3, \A3, \U0
    lw      \S0, 0(\A0)
    lw      \S1, 0(\A1)
    lw      \S2, 0(\A2)
    lw      \S3, 0(\A3)                 // All TBOX 0 accesses
    srli    \T0, \T0, 6
    srli    \T1, \T1, 6
    srli    \T2, \T2, 6
    srli    \T3, \T3, 6
    andi    \A0, \T0, 0xFF<<2
    andi    \A1, \T1, 0xFF<<2
    andi    \A2, \T2, 0xFF<<2
    andi    \A3, \T3, 0xFF<<2
    add     \TX, \A1, \U1               // A* = TBOX_1 + (t* >> 8)
    add     \A1, \A2, \U1
    add     \A2, \A3, \U1
    add     \A3, \A0, \U1
    lw      \A0, 0(\TX)                 // All TBOX 1 accesses
    lw      \A1, 0(\A1)
    lw      \A2, 0(\A2)
    lw      \A3, 0(\A3)
    xor     \S0, \S0, \A0               // Accumulate
    xor     \S1, \S1, \A1
    xor     \S2, \S2, \A2
    xor     \S3, \S3, \A3
    srli    \T0, \T0, 8
    srli    \T1, \T1, 8
    srli    \T2, \T2, 8
    srli    \T3, \T3, 8
    andi    \A0, \T0, 0xFF<<2
    andi    \A1, \T1, 0xFF<<2
    andi    \A2, \T2, 0xFF<<2
    andi    \A3, \T3, 0xFF<<2
    add     \TX, \A2, \U2               // A* = TBOX_2 + (t* >> 16)
    add     \TY, \A3, \U2
    add     \A2, \A0, \U2
    add     \A3, \A1, \U2
    lw      \A0, 0(\TX)                 // All TBOX 2 accesses
    lw      \A1, 0(\TY)
    lw      \A2, 0(\A2)
    lw      \A3, 0(\A3)
    xor     \S0, \S0, \A0               // Accumulate
    xor     \S1, \S1, \A1
    xor     \S2, \S2, \A2
    xor     \S3, \S3, \A3
    srli    \T0, \T0, 8
    srli    \T1, \T1, 8
    srli    \T2, \T2, 8
    srli    \T3, \T3, 8
    andi    \A0, \T0, 0xFF<<2
    andi    \A1, \T1, 0xFF<<2
    andi    \A2, \T2, 0xFF<<2
    andi    \A3, \T3, 0xFF<<2
    add     \TX, \A3, \U3               // A* = TBOX_3 + (t* >> 24)
    add     \TY, \A0, \U3
    add     \TZ, \A1, \U3
    add     \A3, \A2, \U3
    lw      \A0, 0(\TX)                 // All TBOX 3 accesses
    lw      \A1, 0(\TY)
    lw      \A2, 0(\TZ)
    lw      \A3, 0(\A3)
    xor     \T0, \S0, \A0               // Accumulate
    xor     \T1, \S1, \A1
    xor     \T2, \S2, \A2
    xor     \T3, \S3, \A3
    lw      \S0, 0(\RK)                 // Roundkey accesses
    lw      \S1, 4(\RK)                 
    lw      \S2, 8(\RK)                 
    lw      \S3,12(\RK)                 
    xor     \T0, \T0, \S0               // Add Round Key
    xor     \T1, \T1, \S1
    xor     \T2, \T2, \S2
    xor     \T3, \T3, \S3
.endm



.macro T_ENC_LOOKUP_FIN T0, T1, T2, T3, RK, U0,U1,U2,U3, A0, A1, A2, A3, S0, S1, S2, S3, TX, TY, TZ
    li      \U1, 0xFF
    andi    \A0, \T0, 0xFF
    andi    \A1, \T1, 0xFF
    andi    \A2, \T2, 0xFF
    andi    \A3, \T3, 0xFF
    slli    \A0, \A0, 2
    slli    \A1, \A1, 2
    slli    \A2, \A2, 2
    slli    \A3, \A3, 2
    add     \A0, \A0, \U0               // A* = TBOX_4 + (t* >> 0)
    add     \A1, \A1, \U0
    add     \A2, \A2, \U0
    add     \A3, \A3, \U0
    lw      \S0, 0(\A0)
    lw      \S1, 0(\A1)
    lw      \S2, 0(\A2)
    lw      \S3, 0(\A3)                 // All TBOX 4 accesses
    and     \S0, \S0, \U1               // Mask bytes
    and     \S1, \S1, \U1
    and     \S2, \S2, \U1
    and     \S3, \S3, \U1
    slli    \U1, \U1, 8                 // Shift up mask 8 bits
    srli    \T0, \T0, 6
    srli    \T1, \T1, 6
    srli    \T2, \T2, 6
    srli    \T3, \T3, 6
    andi    \A0, \T0, 0xFF<<2
    andi    \A1, \T1, 0xFF<<2
    andi    \A2, \T2, 0xFF<<2
    andi    \A3, \T3, 0xFF<<2
    add     \TX, \A1, \U0               // A* = TBOX_4 + (t* >> 8)
    add     \A1, \A2, \U0
    add     \A2, \A3, \U0
    add     \A3, \A0, \U0
    lw      \A0, 0(\TX)                 // All TBOX 4 accesses
    lw      \A1, 0(\A1)
    lw      \A2, 0(\A2)
    lw      \A3, 0(\A3)
    and     \A0, \A0, \U1               // Mask bytes
    and     \A1, \A1, \U1
    and     \A2, \A2, \U1
    and     \A3, \A3, \U1
    slli    \U1, \U1, 8                 // Shift up mask 8 bits
    xor     \S0, \S0, \A0               // Accumulate
    xor     \S1, \S1, \A1
    xor     \S2, \S2, \A2
    xor     \S3, \S3, \A3
    srli    \T0, \T0, 8
    srli    \T1, \T1, 8
    srli    \T2, \T2, 8
    srli    \T3, \T3, 8
    andi    \A0, \T0, 0xFF<<2
    andi    \A1, \T1, 0xFF<<2
    andi    \A2, \T2, 0xFF<<2
    andi    \A3, \T3, 0xFF<<2
    add     \TX, \A2, \U0               // A* = TBOX_4 + (t* >> 16)
    add     \TY, \A3, \U0
    add     \A2, \A0, \U0
    add     \A3, \A1, \U0
    lw      \A0, 0(\TX)                 // All TBOX 4 accesses
    lw      \A1, 0(\TY)
    lw      \A2, 0(\A2)
    lw      \A3, 0(\A3)
    and     \A0, \A0, \U1               // Mask bytes
    and     \A1, \A1, \U1
    and     \A2, \A2, \U1
    and     \A3, \A3, \U1
    slli    \U1, \U1, 8                 // Shift up mask 8 bits
    xor     \S0, \S0, \A0               // Accumulate
    xor     \S1, \S1, \A1
    xor     \S2, \S2, \A2
    xor     \S3, \S3, \A3
    srli    \T0, \T0, 8
    srli    \T1, \T1, 8
    srli    \T2, \T2, 8
    srli    \T3, \T3, 8
    andi    \A0, \T0, 0xFF<<2
    andi    \A1, \T1, 0xFF<<2
    andi    \A2, \T2, 0xFF<<2
    andi    \A3, \T3, 0xFF<<2
    add     \TX, \A3, \U0               // A* = TBOX_4 + (t* >> 24)
    add     \TY, \A0, \U0
    add     \TZ, \A1, \U0
    add     \A3, \A2, \U0
    lw      \A0, 0(\TX)                 // All TBOX 4 accesses
    lw      \A1, 0(\TY)
    lw      \A2, 0(\TZ)
    lw      \A3, 0(\A3)
    and     \A0, \A0, \U1               // Mask bytes
    and     \A1, \A1, \U1
    and     \A2, \A2, \U1
    and     \A3, \A3, \U1
    slli    \U1, \U1, 8                 // Shift up mask 8 bits
    xor     \T0, \S0, \A0               // Accumulate
    xor     \T1, \S1, \A1
    xor     \T2, \S2, \A2
    xor     \T3, \S3, \A3
    lw      \S0, 0(\RK)                 // Roundkey accesses
    lw      \S1, 4(\RK)                 
    lw      \S2, 8(\RK)                 
    lw      \S3,12(\RK)                 
    xor     \T0, \T0, \S0               // Add Round Key
    xor     \T1, \T1, \S1
    xor     \T2, \T2, \S2
    xor     \T3, \T3, \S3
.endm



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
    
    #define S0 s0
    #define S1 s1
    #define S2 s2
    #define S3 s3

    #define TX s4
    #define TY s5
    #define TZ s6

    #define A0 a1
    #define A1 t4
    #define A2 t5
    #define A3 t6

    #define CT a0
    #define PT a1
    #define RK a2
    #define NR a3
    #define KP a3

    addi    sp, sp, -32
    sw      S0, 0(sp)
    sw      S1, 4(sp)
    sw      S2, 8(sp)
    sw      S3,12(sp)
    sw      TX,16(sp)
    sw      TY,20(sp)
    sw      TZ,24(sp)

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

    la      U0, AES_ENC_TBOX_0                  // Base addresses of luts.
    la      U1, AES_ENC_TBOX_1
    la      U2, AES_ENC_TBOX_2
    la      U3, AES_ENC_TBOX_3

.aes_enc_block_l0:

        T_ENC_LOOKUP_RND T0, T1, T2, T3, RK, U0, U1, U2, U3, \
                         A0, A1, A2, A3, S0, S1, S2, S3, TX, TY, TZ
    
        addi    RK, RK, 16                      // Move to next round key.

    bne RK, KP, .aes_enc_block_l0               // Repeat loop

.aes_enc_block_l_finish:
    
    la U0, AES_ENC_TBOX_4

    T_ENC_LOOKUP_FIN T0, T1, T2, T3, RK, U0, U1, U2, U3, \
                     A0, A1, A2, A3, S0, S1, S2, S3, TX, TY, TZ

    AES_DUMP_STATE  T0, T1, T2, T3, CT
    
    lw      S0, 0(sp)
    lw      S1, 4(sp)
    lw      S2, 8(sp)
    lw      S3,12(sp)
    lw      TX,16(sp)
    lw      TY,20(sp)
    lw      TZ,24(sp)
    addi    sp, sp, 32

    ret
    
    #undef T0
    #undef T1
    #undef T2
    #undef T3
    
    #undef U0
    #undef U1
    #undef U2
    #undef U3
    
    #undef S0
    #undef S1
    #undef S2
    #undef S3

    #undef TX
    #undef TY
    #undef TZ

    #undef A0
    #undef A1
    #undef A2
    #undef A3

    #undef CT
    #undef PT
    #undef RK
    #undef NR
    #undef KP

.endfunc




.macro T_DEC_LOOKUP_RND T0, T1, T2, T3, RK, U0, U1, U2, U3, A0, A1, A2, A3, S0, S1, S2, S3, TX, TY, TZ
    andi    \A0, \T0, 0xFF
    andi    \A1, \T1, 0xFF
    andi    \A2, \T2, 0xFF
    andi    \A3, \T3, 0xFF
    slli    \A0, \A0, 2
    slli    \A1, \A1, 2
    slli    \A2, \A2, 2
    slli    \A3, \A3, 2
    add     \A0, \A0, \U0               // A* = TBOX_0 + (t* >> 0)
    add     \A1, \A1, \U0
    add     \A2, \A2, \U0
    add     \A3, \A3, \U0
    lw      \S0, 0(\A0)
    lw      \S1, 0(\A1)
    lw      \S2, 0(\A2)
    lw      \S3, 0(\A3)                 // All TBOX 0 accesses
    srli    \T0, \T0, 6
    srli    \T1, \T1, 6
    srli    \T2, \T2, 6
    srli    \T3, \T3, 6
    andi    \A0, \T0, 0xFF<<2
    andi    \A1, \T1, 0xFF<<2
    andi    \A2, \T2, 0xFF<<2
    andi    \A3, \T3, 0xFF<<2
    add     \TX, \A3, \U1               // A* = TBOX_1 + (t* >> 8)
    add     \TY, \A0, \U1
    add     \TZ, \A1, \U1
    add     \A3, \A2, \U1
    lw      \A0, 0(\TX)                 // All TBOX 1 accesses
    lw      \A1, 0(\TY)
    lw      \A2, 0(\TZ)
    lw      \A3, 0(\A3)
    xor     \S0, \S0, \A0               // Accumulate
    xor     \S1, \S1, \A1
    xor     \S2, \S2, \A2
    xor     \S3, \S3, \A3
    srli    \T0, \T0, 8
    srli    \T1, \T1, 8
    srli    \T2, \T2, 8
    srli    \T3, \T3, 8
    andi    \A0, \T0, 0xFF<<2
    andi    \A1, \T1, 0xFF<<2
    andi    \A2, \T2, 0xFF<<2
    andi    \A3, \T3, 0xFF<<2
    add     \TX, \A2, \U2               // A* = TBOX_2 + (t* >> 16)
    add     \TY, \A3, \U2
    add     \A2, \A0, \U2
    add     \A3, \A1, \U2
    lw      \A0, 0(\TX)                 // All TBOX 2 accesses
    lw      \A1, 0(\TY)
    lw      \A2, 0(\A2)
    lw      \A3, 0(\A3)
    xor     \S0, \S0, \A0               // Accumulate
    xor     \S1, \S1, \A1
    xor     \S2, \S2, \A2
    xor     \S3, \S3, \A3
    srli    \T0, \T0, 8
    srli    \T1, \T1, 8
    srli    \T2, \T2, 8
    srli    \T3, \T3, 8
    andi    \A0, \T0, 0xFF<<2
    andi    \A1, \T1, 0xFF<<2
    andi    \A2, \T2, 0xFF<<2
    andi    \A3, \T3, 0xFF<<2
    add     \TX, \A1, \U3               // A* = TBOX_3 + (t* >> 24)
    add     \A1, \A2, \U3
    add     \A2, \A3, \U3
    add     \A3, \A0, \U3
    lw      \A0, 0(\TX)                 // All TBOX 3 accesses
    lw      \A1, 0(\A1)
    lw      \A2, 0(\A2)
    lw      \A3, 0(\A3)
    xor     \T0, \S0, \A0               // Accumulate
    xor     \T1, \S1, \A1
    xor     \T2, \S2, \A2
    xor     \T3, \S3, \A3
    lw      \S0, 0(\RK)                 // Roundkey accesses
    lw      \S1, 4(\RK)                 
    lw      \S2, 8(\RK)                 
    lw      \S3,12(\RK)                 
    xor     \T0, \T0, \S0               // Add Round Key
    xor     \T1, \T1, \S1
    xor     \T2, \T2, \S2
    xor     \T3, \T3, \S3
.endm



.macro T_DEC_LOOKUP_FIN T0, T1, T2, T3, RK, U0,U1,U2,U3, A0, A1, A2, A3, S0, S1, S2, S3, TX, TY, TZ
    li      \U1, 0xFF
    andi    \A0, \T0, 0xFF
    andi    \A1, \T1, 0xFF
    andi    \A2, \T2, 0xFF
    andi    \A3, \T3, 0xFF
    slli    \A0, \A0, 2
    slli    \A1, \A1, 2
    slli    \A2, \A2, 2
    slli    \A3, \A3, 2
    add     \A0, \A0, \U0               // A* = TBOX_4 + (t* >> 0)
    add     \A1, \A1, \U0
    add     \A2, \A2, \U0
    add     \A3, \A3, \U0
    lw      \S0, 0(\A0)
    lw      \S1, 0(\A1)
    lw      \S2, 0(\A2)
    lw      \S3, 0(\A3)                 // All TBOX 4 accesses
    and     \S0, \S0, \U1               // Mask bytes
    and     \S1, \S1, \U1
    and     \S2, \S2, \U1
    and     \S3, \S3, \U1
    slli    \U1, \U1, 8                 // Shift up mask 8 bits
    srli    \T0, \T0, 6
    srli    \T1, \T1, 6
    srli    \T2, \T2, 6
    srli    \T3, \T3, 6
    andi    \A0, \T0, 0xFF<<2
    andi    \A1, \T1, 0xFF<<2
    andi    \A2, \T2, 0xFF<<2
    andi    \A3, \T3, 0xFF<<2
    add     \TX, \A3, \U0               // A* = TBOX_4 + (t* >> 8)
    add     \TY, \A0, \U0
    add     \TZ, \A1, \U0
    add     \A3, \A2, \U0
    lw      \A0, 0(\TX)                 // All TBOX 4 accesses
    lw      \A1, 0(\TY)
    lw      \A2, 0(\TZ)
    lw      \A3, 0(\A3)
    and     \A0, \A0, \U1               // Mask bytes
    and     \A1, \A1, \U1
    and     \A2, \A2, \U1
    and     \A3, \A3, \U1
    slli    \U1, \U1, 8                 // Shift up mask 8 bits
    xor     \S0, \S0, \A0               // Accumulate
    xor     \S1, \S1, \A1
    xor     \S2, \S2, \A2
    xor     \S3, \S3, \A3
    srli    \T0, \T0, 8
    srli    \T1, \T1, 8
    srli    \T2, \T2, 8
    srli    \T3, \T3, 8
    andi    \A0, \T0, 0xFF<<2
    andi    \A1, \T1, 0xFF<<2
    andi    \A2, \T2, 0xFF<<2
    andi    \A3, \T3, 0xFF<<2
    add     \TX, \A2, \U0               // A* = TBOX_4 + (t* >> 16)
    add     \TY, \A3, \U0
    add     \A2, \A0, \U0
    add     \A3, \A1, \U0
    lw      \A0, 0(\TX)                 // All TBOX 4 accesses
    lw      \A1, 0(\TY)
    lw      \A2, 0(\A2)
    lw      \A3, 0(\A3)
    and     \A0, \A0, \U1               // Mask bytes
    and     \A1, \A1, \U1
    and     \A2, \A2, \U1
    and     \A3, \A3, \U1
    slli    \U1, \U1, 8                 // Shift up mask 8 bits
    xor     \S0, \S0, \A0               // Accumulate
    xor     \S1, \S1, \A1
    xor     \S2, \S2, \A2
    xor     \S3, \S3, \A3
    srli    \T0, \T0, 8
    srli    \T1, \T1, 8
    srli    \T2, \T2, 8
    srli    \T3, \T3, 8
    andi    \A0, \T0, 0xFF<<2
    andi    \A1, \T1, 0xFF<<2
    andi    \A2, \T2, 0xFF<<2
    andi    \A3, \T3, 0xFF<<2
    add     \TX, \A1, \U0               // A* = TBOX_4 + (t* >> 24)
    add     \TY, \A2, \U0
    add     \TZ, \A3, \U0
    add     \A3, \A0, \U0
    lw      \A0, 0(\TX)                 // All TBOX 4 accesses
    lw      \A1, 0(\TY)
    lw      \A2, 0(\TZ)
    lw      \A3, 0(\A3)
    and     \A0, \A0, \U1               // Mask bytes
    and     \A1, \A1, \U1
    and     \A2, \A2, \U1
    and     \A3, \A3, \U1
    slli    \U1, \U1, 8                 // Shift up mask 8 bits
    xor     \T0, \S0, \A0               // Accumulate
    xor     \T1, \S1, \A1
    xor     \T2, \S2, \A2
    xor     \T3, \S3, \A3
    lw      \S0, 0(\RK)                 // Roundkey accesses
    lw      \S1, 4(\RK)                 
    lw      \S2, 8(\RK)                 
    lw      \S3,12(\RK)                 
    xor     \T0, \T0, \S0               // Add Round Key
    xor     \T1, \T1, \S1
    xor     \T2, \T2, \S2
    xor     \T3, \T3, \S3
.endm



.func   aes_dec_block                           // a0 - uint8_t     ct [16],
.global aes_dec_block                           // a1 - uint8_t     pt [16],
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
    
    #define S0 s0
    #define S1 s1
    #define S2 s2
    #define S3 s3

    #define TX s4
    #define TY s5
    #define TZ s6

    #define A0 a1
    #define A1 t4
    #define A2 t5
    #define A3 t6

    #define CT a0
    #define PT a1
    #define RK a2
    #define NR a3
    #define KP a3

    addi    sp, sp, -32
    sw      S0, 0(sp)
    sw      S1, 4(sp)
    sw      S2, 8(sp)
    sw      S3,12(sp)
    sw      TX,16(sp)
    sw      TY,20(sp)
    sw      TZ,24(sp)

    slli    KP, NR, 4
    add     KP, KP, RK                          // kp = rk + 4*nr

    AES_LOAD_STATE T0,T1,T2,T3,PT,U0,U1,U2,U3   // Columns in T*


    lw      U0,  0(KP)                          // Load Round Key
    lw      U1,  4(KP)
    lw      U2,  8(KP)
    lw      U3, 12(KP)

    xor     T0, T0, U0                          // Add Round Key
    xor     T1, T1, U1
    xor     T2, T2, U2
    xor     T3, T3, U3
    
    addi    KP, KP, -16                          // Move to next round key.

    la      U0, AES_DEC_TBOX_0                  // Base addresses of luts.
    la      U1, AES_DEC_TBOX_1
    la      U2, AES_DEC_TBOX_2
    la      U3, AES_DEC_TBOX_3
    

.aes_dec_block_l0:

        T_DEC_LOOKUP_RND T0, T1, T2, T3, KP, U0, U1, U2, U3, \
                         A0, A1, A2, A3, S0, S1, S2, S3, TX, TY, TZ

        addi    KP, KP, -16                      // Move to next round key.

    bne RK, KP, .aes_dec_block_l0               // Repeat loop

.aes_dec_block_l_finish:
    
    la U0, AES_DEC_TBOX_4

    T_DEC_LOOKUP_FIN T0, T1, T2, T3, KP, U0, U1, U2, U3, \
                     A0, A1, A2, A3, S0, S1, S2, S3, TX, TY, TZ

    AES_DUMP_STATE  T0, T1, T2, T3, CT
    
    lw      S0, 0(sp)
    lw      S1, 4(sp)
    lw      S2, 8(sp)
    lw      S3,12(sp)
    lw      TX,16(sp)
    lw      TY,20(sp)
    lw      TZ,24(sp)
    addi    sp, sp, 32

    ret
    
    #undef T0
    #undef T1
    #undef T2
    #undef T3
    
    #undef U0
    #undef U1
    #undef U2
    #undef U3
    
    #undef S0
    #undef S1
    #undef S2
    #undef S3

    #undef TX
    #undef TY
    #undef TZ

    #undef A0
    #undef A1
    #undef A2
    #undef A3

    #undef CT
    #undef PT
    #undef RK
    #undef NR
    #undef KP

.endfunc
