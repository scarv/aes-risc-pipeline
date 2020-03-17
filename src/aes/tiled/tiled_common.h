
#ifndef AES_TILED_COMMON_H
#define AES_TILED_COMMON_H

#define  PACK_QUAD_0(D, C0, C1) { D = (C1 &  0x0000FFFF) | (C0 << 16); }
#define  PACK_QUAD_1(D, C2, C3) { D = (C3 &  0x0000FFFF) | (C2 << 16); }
#define  PACK_QUAD_2(D, C0, C1) { D = (C0 &  0xFFFF0000) | (C1 >> 16); }
#define  PACK_QUAD_3(D, C2, C3) { D = (C2 &  0xFFFF0000) | (C3 >> 16); }

#define UNPACK_COL_0(D, Q0, Q2) { D = (Q0 >>         16) | (Q2 & 0xFFFF0000);}
#define UNPACK_COL_1(D, Q0, Q2) { D = (Q0 &  0x0000FFFF) | (Q2 << 16       );}
#define UNPACK_COL_2(D, Q1, Q3) { D = (Q1 >>         16) | (Q3 & 0xFFFF0000);}
#define UNPACK_COL_3(D, Q1, Q3) { D = (Q1 &  0x0000FFFF) | (Q3 << 16       );}

#endif

