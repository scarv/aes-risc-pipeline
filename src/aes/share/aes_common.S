
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

#endif

