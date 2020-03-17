
#include <stdint.h>
#include <stddef.h>

#ifndef __RISCV_CRYPTO_INTRINSICS__
#define __RISCV_CRYPTO_INTRINSICS__

#if __riscv_xlen == 32
#define RISCV_CRYPTO_RV32
#endif

#if __riscv_xlen == 64
#define RISCV_CRYPTO_RV64
#endif

//
// AES
//

static inline uint32_t _saes_v1_encs(uint32_t rs1) {uint32_t rd; __asm__("saes.v1.encs %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline uint32_t _saes_v1_encm(uint32_t rs1) {uint32_t rd; __asm__("saes.v1.encm %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline uint32_t _saes_v1_decs(uint32_t rs1) {uint32_t rd; __asm__("saes.v1.decs %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline uint32_t _saes_v1_decm(uint32_t rs1) {uint32_t rd; __asm__("saes.v1.decm %0, %1" : "=r"(rd) : "r"(rs1)); return rd;}

static inline uint32_t _saes_v2_sub_enc   (uint32_t rs1, uint32_t rs2) {uint32_t rd; __asm__("saes.v2.sub.enc    %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint32_t _saes_v2_sub_encrot(uint32_t rs1, uint32_t rs2) {uint32_t rd; __asm__("saes.v2.sub.encrot %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint32_t _saes_v2_sub_dec   (uint32_t rs1, uint32_t rs2) {uint32_t rd; __asm__("saes.v2.sub.dec    %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint32_t _saes_v2_sub_decrot(uint32_t rs1, uint32_t rs2) {uint32_t rd; __asm__("saes.v2.sub.decrot %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint32_t _saes_v2_mix_enc   (uint32_t rs1, uint32_t rs2) {uint32_t rd; __asm__("saes.v2.mix.enc    %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint32_t _saes_v2_mix_dec   (uint32_t rs1, uint32_t rs2) {uint32_t rd; __asm__("saes.v2.mix.dec    %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}

static inline uint32_t _saes_v3_encs (uint32_t rs1, uint32_t rs2, int bs) {uint32_t rd; __asm__("saes.v3.encs  %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd;}
static inline uint32_t _saes_v3_encm (uint32_t rs1, uint32_t rs2, int bs) {uint32_t rd; __asm__("saes.v3.encm  %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd;}
static inline uint32_t _saes_v3_encsm(uint32_t rs1, uint32_t rs2, int bs) {uint32_t rd; __asm__("saes.v3.encsm %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd;}
static inline uint32_t _saes_v3_decs (uint32_t rs1, uint32_t rs2, int bs) {uint32_t rd; __asm__("saes.v3.decs  %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd;}
static inline uint32_t _saes_v3_decm (uint32_t rs1, uint32_t rs2, int bs) {uint32_t rd; __asm__("saes.v3.decm  %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd;}
static inline uint32_t _saes_v3_decsm(uint32_t rs1, uint32_t rs2, int bs) {uint32_t rd; __asm__("saes.v3.decsm %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd;}

#endif // __RISCV_CRYPTO_INTRINSICS__


