
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

    lw      \T0, 0(\CK)
    lw      \T1, 4(\CK)
    lw      \T2, 8(\CK)
    lw      \T3,12(\CK)

.endm

//
// Dump the AES state from column-wise registers into a byte-aligned array.
//
.macro AES_DUMP_STATE T0, T1, T2, T3, CT

    sw      \T0, 0(\CT)
    sw      \T1, 4(\CT)
    sw      \T2, 8(\CT)
    sw      \T3,12(\CT)

.endm

#endif // __AES_COMMON_S__
