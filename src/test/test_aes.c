
#include <stdlib.h>
#include <string.h>

#include "test_util.h"

#include "aes.h"

// Start with known inputs from FIPS 197, Appendix B.
uint8_t  key [AES_128_CK_BYTES ] = {0x2b ,0x7e ,0x15 ,0x16 ,0x28 ,0xae ,0xd2 ,0xa6 ,0xab ,0xf7 ,0x15 ,0x88 ,0x09 ,0xcf ,0x4f ,0x3c};
uint8_t  pt  [16   ] = {0x32 ,0x43 ,0xf6 ,0xa8 ,0x88 ,0x5a ,0x30 ,0x8d ,0x31 ,0x31 ,0x98 ,0xa2 ,0xe0 ,0x37 ,0x07 ,0x34};
uint32_t erk [AES_128_RK_BYTES  ]; //!< Roundkeys (encrypt)
uint32_t drk [AES_128_RK_BYTES  ]; //!< Roundkeys (decrypt)
uint8_t  ct  [16   ];
uint8_t  pt2 [16   ];

int main(int argc, char ** argv) {

    printf("import sys, binascii, Crypto.Cipher.AES as AES\n");
    printf("benchmark_name = 'aes'\n");

    const int num_tests = 10;

    uint64_t start_instrs;

    for(int i = 0; i < num_tests; i ++) {

        start_instrs = test_rdinstret();
        aes_128_enc_key_schedule(erk, key    );
        uint64_t kse_icount   = test_rdinstret() - start_instrs;

        start_instrs = test_rdinstret();
        aes_128_enc_block       (ct , pt, erk);
        uint64_t enc_icount   = test_rdinstret() - start_instrs;
        
        start_instrs = test_rdinstret();
        aes_128_dec_key_schedule(drk, key    );
        uint64_t ksd_icount   = test_rdinstret() - start_instrs;

        start_instrs = test_rdinstret();
        aes_128_dec_block       (pt2, ct, drk);
        uint64_t dec_icount   = test_rdinstret() - start_instrs;
        
        printf("#\n# test %d/%d\n",i , num_tests);

        printf("key             = ");
        puthex_py(key, AES_128_CK_BYTES);
        printf("\n");
        
        printf("erk             = ");
        puthex_py((uint8_t*)erk , AES_128_RK_BYTES );
        printf("\n");

//#define UNPACK_COL_0(D, Q0, Q2) { D = (Q0 >>         16) | (Q2 & 0xFFFF0000);}
//#define UNPACK_COL_1(D, Q0, Q2) { D = (Q0 &  0x0000FFFF) | (Q2 << 16       );}
//#define UNPACK_COL_2(D, Q1, Q3) { D = (Q1 >>         16) | (Q3 & 0xFFFF0000);}
//#define UNPACK_COL_3(D, Q1, Q3) { D = (Q1 &  0x0000FFFF) | (Q3 << 16       );}
//
//        for(int i = 0; i < AES_128_RK_WORDS; i += 4) {
//            uint32_t c0,c1,c2,c3;
//            UNPACK_COL_0(c0, erk[i+0], erk[i+2]);
//            UNPACK_COL_1(c1, erk[i+0], erk[i+2]);
//            UNPACK_COL_2(c2, erk[i+1], erk[i+3]);
//            UNPACK_COL_3(c3, erk[i+1], erk[i+3]);
//            printf("# %08X %08X\n"  , BS32(c0), BS32(erk[i+0]));
//            printf("# %08X %08X\n"  , BS32(c1), BS32(erk[i+1]));
//            printf("# %08X %08X\n"  , BS32(c2), BS32(erk[i+2]));
//            printf("# %08X %08X\n\n", BS32(c3), BS32(erk[i+3]));
//        }
        
        printf("drk             = ");
        puthex_py((uint8_t*)drk , AES_128_RK_BYTES );
        printf("\n");

        printf("pt              = ");
        puthex_py(pt , 16  );
        printf("\n");
        
        printf("pt2             = ");
        puthex_py(pt2, 16  );
        printf("\n");

        printf("ct              = ");
        puthex_py(ct , 16  );
        printf("\n");

        printf("kse_icount      = 0x"); puthex64(kse_icount); printf("\n");
        printf("ksd_icount      = 0x"); puthex64(ksd_icount); printf("\n");
        printf("enc_icount      = 0x"); puthex64(enc_icount); printf("\n");
        printf("dec_icount      = 0x"); puthex64(dec_icount); printf("\n");

        printf("testnum         = %d\n",i);

        printf("ref_ct          = AES.new(key).encrypt(pt    )\n");
        printf("ref_pt          = AES.new(key).decrypt(ref_ct)\n");
        printf("if( ref_ct     != ct        ):\n");
        printf("    print(\"Test %d encrypt failed.\")\n", i);
        printf("    print( 'key == %%s' %% ( binascii.b2a_hex( key    )))\n");
        printf("    print( 'rk  == %%s' %% ( binascii.b2a_hex(erk     )))\n");
        printf("    print( 'pt  == %%s' %% ( binascii.b2a_hex( pt     )))\n");
        printf("    print( 'ct  == %%s' %% ( binascii.b2a_hex( ct     )))\n");
        printf("    print( '    != %%s' %% ( binascii.b2a_hex( ref_ct )))\n");
        printf("    sys.exit(1)\n");
        printf("elif( ref_pt     != pt2       ):\n");
        printf("    print(\"Test %d decrypt failed.\")\n", i);
        printf("    print( 'key == %%s' %% ( binascii.b2a_hex( key    )))\n");
        printf("    print( 'rk  == %%s' %% ( binascii.b2a_hex(drk     )))\n");
        printf("    print( 'ct  == %%s' %% ( binascii.b2a_hex( ct     )))\n");
        printf("    print( 'pt  == %%s' %% ( binascii.b2a_hex( pt2    )))\n");
        printf("    print( '    != %%s' %% ( binascii.b2a_hex( ref_pt )))\n");
        printf("    sys.exit(1)\n");
        printf("else:\n");
        printf("    sys.stdout.write(\"aes Test passed.\")\n");
        printf("    sys.stdout.write(\"enc: %%d, \" %% (enc_icount))\n");
        printf("    sys.stdout.write(\"dec: %%d, \" %% (dec_icount))\n");
        printf("    sys.stdout.write(\"kse: %%d, \" %% (kse_icount))\n");
        printf("    sys.stdout.write(\"ksd: %%d, \" %% (ksd_icount))\n");
        printf("    print(\"\")\n");
        
        // New random inputs
        test_rdrandom(pt    , 16   );
        test_rdrandom(key   , AES_128_CK_BYTES );

    }

    return 0;

}
