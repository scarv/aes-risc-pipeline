
/*!
@defgroup test_utils Test Utils
@{
*/

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#ifndef __SHARE_TEST_H__
#define __SHARE_TEST_H__

//! Length of test input for a hash function.
#define TEST_HASH_INPUT_LENGTH 1024

#define BS32(X) ( \
    ((X & 0xFF000000) >> 24) | \
    ((X & 0x00FF0000) >>  8) | \
    ((X & 0x0000FF00) <<  8) | \
    ((X & 0x000000FF) << 24)  \
)

#define MEASURE_BEGIN(NAME) { \
    uint32_t instr_start, instr_end                     ; \
    uint32_t cycle_start, cycle_end                     ; \
    asm volatile("rdcycle   %0" : "=r"(cycle_start))    ; \
    asm volatile("rdinstret %0" : "=r"(instr_start))    ;
 


#define MEASURE_END(NAME,I,C)   \
    asm volatile("rdcycle   %0" : "=r"(cycle_end))      ; \
    asm volatile("rdinstret %0" : "=r"(instr_end))      ; \
    I  = instr_end - instr_start; \
    C  = cycle_end - cycle_start; \
}

//
// Misc
// ----------------------------------------------------------------------

/*!
@brief Prints a 64-bit input as hex to stdout.
@details Prints in LITTLE ENDIAN mode.
@param [in] in - The thing to print.
*/
void puthex64(uint64_t in);


/*!
@brief Prints a byte string as hex to std out in little endian mode.
@param [in] in - The byte string to print.
@param [in] len - Length of the string to print.
*/
void puthex(unsigned char * in, size_t len);


/*!
@brief Prints a byte string such that it can be read by a python program as
    a giant literal.
@param [in] in - The byte string to print.
@param [in] len - Length of the string to print.
*/
void puthex_py(unsigned char * in, size_t len);


/*!
@brief Read len random bytes into dest.
*/
size_t test_rdrandom(unsigned char * dest, size_t len);



//
// Low level register access.
// ------------------------------------------------------------------

/*!
@brief Read the `minstret` CSR register to get instructions retired.
*/
volatile uint64_t test_rdinstret();


/*!
@brief Read the `mcycle` CSR register to get cycles elapsed.
*/
volatile uint64_t test_rdcycle();


/*!
@brief Read the `mtime` CSR register to get *time* elapsed.
@note This may simply be identical to __rdcycle depending on the platform.
*/
volatile uint64_t test_rdtime();

#endif

//! @}
