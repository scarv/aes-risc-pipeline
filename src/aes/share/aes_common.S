
#ifndef __AES_COMMON_S__
#define __AES_COMMON_S__

//
// Rotate value in RS1 right by IMM. Use TMP as scratch regiser.
// RD may equal RS1. TMP may not equal RD or RS1.
.macro ROR32I RD, TMP, RS1, IMM
    srli    \TMP, \RS1, \IMM
    slli    \RD , \RS1, (32-\IMM)
    or      \RD , \RD , \TMP
.endm

//
// Pack low half of RS1 with low half of RS2
// RD != TMP, LM is the low halfword mask register containing 0x0000FFFF
.macro PACK  RD, TMP, RS1, RS2, LM
    and     \RD , \RS1, \LM
    slli    \TMP, \RS2, 16
    or      \RD , \RD , \TMP
.endm

//
// Pack high half of RS1 with high half of RS2
// RD != TMP, HM is the High halfword mask register containing 0xFFFF0000
.macro PACKH RD, TMP, RS1, RS2, HM
    and     \RD , \RS1, \HM
    srli    \TMP, \RS2, 16
    or      \RD , \RD , \TMP
.endm

//
// Pack high half of RS2 with low half of RS1
// RD != TMP
.macro PACKHL RD, TMP, RS1, RS2, HM, LM
    and \TMP, \RS1, \LM
    and \RD , \RS2, \HM
    or  \RD,  \RD , \TMP
.endm

// Performs the AES ShiftRows transoform, putting the results in T*,
// with inputs in U*
.macro AES_SHIFT_ROWS  T0, T1, T2, T3, U0, U1, U2, U3, X1, X2, MSK
    and     \T0, \U0, \MSK
    and     \T1, \U1, \MSK
    and     \T2, \U2, \MSK
    and     \T3, \U3, \MSK
    slli    \X1, \MSK, 8
    and     \X2, \U0, \X1
    or      \T3, \T3, \X2
    and     \X2, \U3, \X1
    or      \T2, \T2, \X2
    and     \X2, \U2, \X1
    or      \T1, \T1, \X2
    and     \X2, \U1, \X1
    or      \T0, \T0, \X2
    slli    \X1, \X1, 8
    and     \X2, \U2, \X1
    or      \T0, \T0, \X2
    and     \X2, \U3, \X1
    or      \T1, \T1, \X2
    and     \X2, \U0, \X1
    or      \T2, \T2, \X2
    and     \X2, \U1, \X1
    or      \T3, \T3, \X2
    slli    \X1, \X1, 8
    and     \X2, \U3, \X1
    or      \T0, \T0, \X2
    and     \X2, \U0, \X1
    or      \T1, \T1, \X2
    and     \X2, \U1, \X1
    or      \T2, \T2, \X2
    and     \X2, \U2, \X1
    or      \T3, \T3, \X2
.endm

// Performs the Inverse AES ShiftRows transoform, putting the results in T*,
// with inputs in U*
.macro AES_INV_SHIFT_ROWS  T0, T1, T2, T3, U0, U1, U2, U3, X1, X2, MSK
    and     \T0, \U0, \MSK
    and     \T1, \U1, \MSK
    and     \T2, \U2, \MSK
    and     \T3, \U3, \MSK
    slli    \X1, \MSK, 8
    and     \X2, \U3, \X1
    or      \T0, \T0, \X2
    and     \X2, \U0, \X1
    or      \T1, \T1, \X2
    and     \X2, \U1, \X1
    or      \T2, \T2, \X2
    and     \X2, \U2, \X1
    or      \T3, \T3, \X2
    slli    \X1, \X1, 8
    and     \X2, \U2, \X1
    or      \T0, \T0, \X2
    and     \X2, \U3, \X1
    or      \T1, \T1, \X2
    and     \X2, \U0, \X1
    or      \T2, \T2, \X2
    and     \X2, \U1, \X1
    or      \T3, \T3, \X2
    slli    \X1, \X1, 8
    and     \X2, \U1, \X1
    or      \T0, \T0, \X2
    and     \X2, \U2, \X1
    or      \T1, \T1, \X2
    and     \X2, \U3, \X1
    or      \T2, \T2, \X2
    and     \X2, \U0, \X1
    or      \T3, \T3, \X2
.endm

//
// Load the byte-aligned AES state from pointer in CK
// - Each column is loaded into the T* registers.
// - The X* registers are temps.
//
.macro AES_LOAD_STATE T0, T1, T2, T3, CK, X0, X1, X2, X3

    lbu     \T0,  3(\CK)
    lbu     \T1,  7(\CK)
    lbu     \T2, 11(\CK)
    lbu     \T3, 15(\CK)
    slli    \T0,\T0, 8
    slli    \T1,\T1, 8
    slli    \T2,\T2, 8
    slli    \T3,\T3, 8
    lbu     \X0,  2(\CK)
    lbu     \X1,  6(\CK)
    lbu     \X2, 10(\CK)
    lbu     \X3, 14(\CK)
    or      \T0, \T0, \X0
    or      \T1, \T1, \X1
    or      \T2, \T2, \X2
    or      \T3, \T3, \X3
    slli    \T0,\T0, 8
    slli    \T1,\T1, 8
    slli    \T2,\T2, 8
    slli    \T3,\T3, 8
    lbu     \X0,  1(\CK)
    lbu     \X1,  5(\CK)
    lbu     \X2,  9(\CK)
    lbu     \X3, 13(\CK)
    or      \T0, \T0, \X0
    or      \T1, \T1, \X1
    or      \T2, \T2, \X2
    or      \T3, \T3, \X3
    slli    \T0,\T0, 8
    slli    \T1,\T1, 8
    slli    \T2,\T2, 8
    slli    \T3,\T3, 8
    lbu     \X0,  0(\CK)
    lbu     \X1,  4(\CK)
    lbu     \X2,  8(\CK)
    lbu     \X3, 12(\CK)
    or      \T0, \T0, \X0
    or      \T1, \T1, \X1
    or      \T2, \T2, \X2
    or      \T3, \T3, \X3

.endm

//
// Dump the AES state from column-wise registers into a byte-aligned array.
//
.macro AES_DUMP_STATE T0, T1, T2, T3, CT
    sb      \T0,  0(\CT)
    sb      \T1,  4(\CT)
    sb      \T2,  8(\CT)
    sb      \T3, 12(\CT)
    srli    \T0, \T0, 8
    srli    \T1, \T1, 8
    srli    \T2, \T2, 8
    srli    \T3, \T3, 8
    sb      \T0,  1(\CT)
    sb      \T1,  5(\CT)
    sb      \T2,  9(\CT)
    sb      \T3, 13(\CT)
    srli    \T0, \T0, 8
    srli    \T1, \T1, 8
    srli    \T2, \T2, 8
    srli    \T3, \T3, 8
    sb      \T0,  2(\CT)
    sb      \T1,  6(\CT)
    sb      \T2, 10(\CT)
    sb      \T3, 14(\CT)
    srli    \T0, \T0, 8
    srli    \T1, \T1, 8
    srli    \T2, \T2, 8
    srli    \T3, \T3, 8
    sb      \T0,  3(\CT)
    sb      \T1,  7(\CT)
    sb      \T2, 11(\CT)
    sb      \T3, 15(\CT)
.endm

#endif

