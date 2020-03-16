// Copyright (C) 2018 SCARV project <info@scarv.org>
//
// Use of this source code is restricted per the MIT license, a copy of which 
// can be found at https://opensource.org/licenses/MIT (or should be included 
// as LICENSE.txt within the associated archive or repository).

#include <stdint.h>

#ifndef AES_H

/*!
@defgroup crypto_block_aes Crypto Block AES
@{

AES  |   Nk  | Nb   | Nr
-----|-------|------|---------------
128  |  4    | 4    | 10
192  |  6    | 4    | 12
256  |  8    | 4    | 14

*/

#ifndef __AES_API_H__
#define __AES_API_H__

#define U32_TO_U8_LE(r,x,i) {                  \
  (r)[ (i) + 0 ] = ( (x) >>  0 ) & 0xFF;       \
  (r)[ (i) + 1 ] = ( (x) >>  8 ) & 0xFF;       \
  (r)[ (i) + 2 ] = ( (x) >> 16 ) & 0xFF;       \
  (r)[ (i) + 3 ] = ( (x) >> 24 ) & 0xFF;       \
}

#define U8_TO_U32_LE(r,x,i) {                  \
  (r)  = ( uint32_t )( (x)[ (i) + 0 ] ) <<  0; \
  (r) |= ( uint32_t )( (x)[ (i) + 1 ] ) <<  8; \
  (r) |= ( uint32_t )( (x)[ (i) + 2 ] ) << 16; \
  (r) |= ( uint32_t )( (x)[ (i) + 3 ] ) << 24; \
}

//! Block size in 4-byte words for AES 128
#define AES_128_NB          4
#define AES_192_NB          4
#define AES_256_NB          4

//! Words in expanded AES 128 cipher key
#define AES_128_NK          4 
#define AES_192_NK          6 
#define AES_256_NK          8 

//! Number of rounds for AES 128
#define AES_128_NR          10
#define AES_192_NR          12
#define AES_256_NR          14

//! Number of 32-bit words in an AES 128 expanded round key.
#define AES_128_RK_WORDS    (4*(AES_128_NR+1))
#define AES_192_RK_WORDS    (4*(AES_192_NR+1))
#define AES_256_RK_WORDS    (4*(AES_256_NR+1))

#define AES_128_RK_BYTES    (4*AES_128_RK_WORDS)
#define AES_192_RK_BYTES    (4*AES_192_RK_WORDS)
#define AES_256_RK_BYTES    (4*AES_256_RK_WORDS)

#define AES_128_CK_BYTES    16
#define AES_192_CK_BYTES    24
#define AES_256_CK_BYTES    32

#define ROTR32(x,c) (((x) >> (c)) | ((x) << (32 - (c))))


//! Key expansion function for the AES 128 parameterisation - encrypt
void    aes_128_enc_key_schedule (
    uint32_t    rk [AES_128_RK_WORDS], //!< [out] The expanded key schedule
    uint8_t     ck [AES_128_CK_BYTES]  //!< [in]  The cipher key to expand
);

//! Key expansion function for the AES 128 parameterisation - decrypt
void    aes_128_dec_key_schedule (
    uint32_t    rk [AES_128_RK_WORDS], //!< [out] The expanded key schedule
    uint8_t     ck [AES_128_CK_BYTES]  //!< [in]  The cipher key to expand
);

//! Key expansion function for the AES 192 parameterisation - encrypt
void    aes_192_enc_key_schedule (
    uint32_t    rk [AES_192_RK_WORDS], //!< [out] The expanded key schedule
    uint8_t     ck [AES_192_CK_BYTES]  //!< [in]  The cipher key to expand
);

//! Key expansion function for the AES 192 parameterisation - decrypt
void    aes_192_dec_key_schedule (
    uint32_t    rk [AES_192_RK_WORDS], //!< [out] The expanded key schedule
    uint8_t     ck [AES_192_CK_BYTES]  //!< [in]  The cipher key to expand
);

//! Key expansion function for the AES 256 parameterisation - encrypt
void    aes_256_enc_key_schedule (
    uint32_t    rk [AES_256_RK_WORDS], //!< [out] The expanded key schedule
    uint8_t     ck [AES_256_CK_BYTES]  //!< [in]  The cipher key to expand
);

//! Key expansion function for the AES 256 parameterisation - decrypt
void    aes_256_dec_key_schedule (
    uint32_t    rk [AES_256_RK_WORDS], //!< [out] The expanded key schedule
    uint8_t     ck [AES_256_CK_BYTES]  //!< [in]  The cipher key to expand
);

//! Block Encrypt function for the AES 128 parameterisation
void    aes_128_enc_block(
    uint8_t     ct [              16], //!< [out] Output ciphertext
    uint8_t     pt [              16], //!< [in] Plaintext to encrypt
    uint32_t    rk [AES_128_RK_WORDS]  //!< [in] The expanded key schedule
);

//! Block Decrypt function for the AES 128 parameterisation
void    aes_128_dec_block(
    uint8_t     pt [              16], //!< [out] Output plaintext
    uint8_t     ct [              16], //!< [in] Ciphertext to encrypt
    uint32_t    rk [AES_128_RK_WORDS]  //!< [in] The expanded key schedule
);

//! Block Encrypt function for the AES 192 parameterisation
void    aes_192_enc_block(
    uint8_t     ct [              16], //!< [out] Output ciphertext
    uint8_t     pt [              16], //!< [in] Plaintext to encrypt
    uint32_t    rk [AES_192_RK_WORDS]  //!< [in] The expanded key schedule
);

//! Block Decrypt function for the AES 192 parameterisation
void    aes_192_dec_block(
    uint8_t     pt [              16], //!< [out] Output plaintext
    uint8_t     ct [              16], //!< [in] Ciphertext to encrypt
    uint32_t    rk [AES_192_RK_WORDS]  //!< [in] The expanded key schedule
);

//! Block Encrypt function for the AES 256 parameterisation
void    aes_256_enc_block(
    uint8_t     ct [              16], //!< [out] Output ciphertext
    uint8_t     pt [              16], //!< [in] Plaintext to encrypt
    uint32_t    rk [AES_256_RK_WORDS]  //!< [in] The expanded key schedule
);

//! Block Decrypt function for the AES 256 parameterisation
void    aes_256_dec_block(
    uint8_t     pt [              16], //!< [out] Output plaintext
    uint8_t     ct [              16], //!< [in] Ciphertext to encrypt
    uint32_t    rk [AES_256_RK_WORDS]  //!< [in] The expanded key schedule
);


#endif

//! @}

#endif
