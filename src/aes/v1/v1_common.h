
#ifndef AES_V1_COMMON_H
#define AES_V1_COMMON_H

#define XT2(x) ((x << 1) ^ (x & 0x80 ? 0x1b : 0x00))
#define XT3(x) (XT2(x) ^ x)
#define XT4(x) XT2(XT2(x))
#define XT8(x) XT2(XT4(x))
#define XT9(x) (XT8(x) ^ x)
#define XTB(x) (XT8(x) ^ XT2(x) ^ x)
#define XTD(x) (XT8(x) ^ XT4(x) ^ x)
#define XTE(x) (XT8(x) ^ XT4(x) ^ XT2(x))

#endif
