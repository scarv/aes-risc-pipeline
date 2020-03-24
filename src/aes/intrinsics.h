
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

#if (defined(RISCV_CRYPTO_RV64))
static inline uint64_t _saes_v4_ks1     (uint64_t rs1, int      rcon) {uint64_t rd; __asm__("saes.v4.ks1      %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(rcon)); return rd;}
static inline uint64_t _saes_v4_ks2     (uint64_t rs1, uint64_t rs2 ) {uint64_t rd; __asm__("saes.v4.ks2      %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2 )); return rd;}
static inline uint64_t _saes_v4_imix    (uint64_t rs1               ) {uint64_t rd; __asm__("saes.v4.imix     %0, %1    " : "=r"(rd) : "r"(rs1)           ); return rd;}
static inline uint64_t _saes_v4_encsm_lo(uint64_t rs1, uint64_t rs2 ) {uint64_t rd; __asm__("saes.v4.encsm.lo %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2 )); return rd;}
static inline uint64_t _saes_v4_encsm_hi(uint64_t rs1, uint64_t rs2 ) {uint64_t rd; __asm__("saes.v4.encsm.hi %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2 )); return rd;}
static inline uint64_t _saes_v4_encs_lo (uint64_t rs1, uint64_t rs2 ) {uint64_t rd; __asm__("saes.v4.encs.lo  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2 )); return rd;}
static inline uint64_t _saes_v4_encs_hi (uint64_t rs1, uint64_t rs2 ) {uint64_t rd; __asm__("saes.v4.encs.hi  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2 )); return rd;}
static inline uint64_t _saes_v4_decsm_lo(uint64_t rs1, uint64_t rs2 ) {uint64_t rd; __asm__("saes.v4.decsm.lo %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2 )); return rd;}
static inline uint64_t _saes_v4_decsm_hi(uint64_t rs1, uint64_t rs2 ) {uint64_t rd; __asm__("saes.v4.decsm.hi %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2 )); return rd;}
static inline uint64_t _saes_v4_decs_lo (uint64_t rs1, uint64_t rs2 ) {uint64_t rd; __asm__("saes.v4.decs.lo  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2 )); return rd;}
static inline uint64_t _saes_v4_decs_hi (uint64_t rs1, uint64_t rs2 ) {uint64_t rd; __asm__("saes.v4.decs.hi  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2 )); return rd;}
#endif

static inline uint32_t _saes_v5_esrsub_hi(uint32_t rs1, uint32_t rs2){uint32_t rd; __asm__("saes.v5.esrsub.hi %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint32_t _saes_v5_dsrsub_hi(uint32_t rs1, uint32_t rs2){uint32_t rd; __asm__("saes.v5.dsrsub.hi %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint32_t _saes_v5_esrsub_lo(uint32_t rs1, uint32_t rs2){uint32_t rd; __asm__("saes.v5.esrsub.lo %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint32_t _saes_v5_dsrsub_lo(uint32_t rs1, uint32_t rs2){uint32_t rd; __asm__("saes.v5.dsrsub.lo %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint32_t _saes_v5_emix     (uint32_t rs1, uint32_t rs2){uint32_t rd; __asm__("saes.v5.emix      %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline uint32_t _saes_v5_dmix     (uint32_t rs1, uint32_t rs2){uint32_t rd; __asm__("saes.v5.dmix      %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}

#endif // __RISCV_CRYPTO_INTRINSICS__


