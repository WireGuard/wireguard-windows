// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2021 Jason A. Donenfeld. All Rights Reserved.
 * Copyright (c) 2020, Google Inc.
 */

#include "crypto.h"
#include <stdint.h>
#include <string.h>
#include <winternl.h>
#include <bcrypt.h>

#if REG_DWORD == REG_DWORD_LITTLE_ENDIAN
#define swap_le64(x) (x)
#define swap_le32(x) (x)
#elif REG_DWORD == REG_DWORD_BIG_ENDIAN
#define swap_le64(x) __builtin_bswap64(x)
#define swap_le32(x) __builtin_bswap32(x)
#endif

static void store_le64(uint8_t *dst, uint64_t src)
{
	src = swap_le64(src);
	__builtin_memcpy(dst, &src, sizeof(src));
}

static uint64_t load_le64(const uint8_t *src)
{
	uint64_t dst;
	__builtin_memcpy(&dst, src, sizeof(dst));
	return swap_le64(dst);
}

static uint32_t load_le24(const uint8_t *in)
{
	uint32_t dst;
	dst = (uint32_t)in[0];
	dst |= ((uint32_t)in[1]) << 8;
	dst |= ((uint32_t)in[2]) << 16;
	return dst;
}

static uint32_t load_le32(const uint8_t *src)
{
	uint32_t dst;
	__builtin_memcpy(&dst, src, sizeof(dst));
	return swap_le32(dst);
}

static uint64_t ror64(uint64_t i, unsigned int s)
{
	return (i >> (s & 63)) | (i << ((-s) & 63));
}

static inline uint32_t value_barrier_u32(uint32_t a)
{
	__asm__("" : "+r"(a) : /* no inputs */);
	return a;
}

static int memcmp_ct(const void *first, const void *second, size_t len)
{
	const uint8_t *a = first;
	const uint8_t *b = second;
	uint8_t diff = 0;

	for (size_t i = 0; i < len; ++i) {
		diff |= a[i] ^ b[i];
		__asm__("" : "+r"(diff) : /* no inputs */);
	}

	return diff;
}

/*
 * The function fiat_25519_addcarryx_u26 is an addition with carry.
 * Postconditions:
 *   out1 = (arg1 + arg2 + arg3) mod 2^26
 *   out2 = ⌊(arg1 + arg2 + arg3) / 2^26⌋
 *
 * Input Bounds:
 *   arg1: [0x0 ~> 0x1]
 *   arg2: [0x0 ~> 0x3ffffff]
 *   arg3: [0x0 ~> 0x3ffffff]
 * Output Bounds:
 *   out1: [0x0 ~> 0x3ffffff]
 *   out2: [0x0 ~> 0x1]
 */
static void fiat_25519_addcarryx_u26(uint32_t *out1, uint8_t *out2,
				     uint8_t arg1, uint32_t arg2, uint32_t arg3)
{
	uint32_t x1 = ((arg1 + arg2) + arg3);
	uint32_t x2 = (x1 & UINT32_C(0x3ffffff));
	uint8_t x3 = (uint8_t)(x1 >> 26);
	*out1 = x2;
	*out2 = x3;
}

/*
 * The function fiat_25519_subborrowx_u26 is a subtraction with borrow.
 * Postconditions:
 *   out1 = (-arg1 + arg2 + -arg3) mod 2^26
 *   out2 = -⌊(-arg1 + arg2 + -arg3) / 2^26⌋
 *
 * Input Bounds:
 *   arg1: [0x0 ~> 0x1]
 *   arg2: [0x0 ~> 0x3ffffff]
 *   arg3: [0x0 ~> 0x3ffffff]
 * Output Bounds:
 *   out1: [0x0 ~> 0x3ffffff]
 *   out2: [0x0 ~> 0x1]
 */
static void fiat_25519_subborrowx_u26(uint32_t *out1, uint8_t *out2,
				      uint8_t arg1, uint32_t arg2,
				      uint32_t arg3)
{
	int32_t x1 = ((int32_t)(arg2 - arg1) - (int32_t)arg3);
	int8_t x2 = (int8_t)(x1 >> 26);
	uint32_t x3 = (x1 & UINT32_C(0x3ffffff));
	*out1 = x3;
	*out2 = (uint8_t)(0x0 - x2);
}

/*
 * The function fiat_25519_addcarryx_u25 is an addition with carry.
 * Postconditions:
 *   out1 = (arg1 + arg2 + arg3) mod 2^25
 *   out2 = ⌊(arg1 + arg2 + arg3) / 2^25⌋
 *
 * Input Bounds:
 *   arg1: [0x0 ~> 0x1]
 *   arg2: [0x0 ~> 0x1ffffff]
 *   arg3: [0x0 ~> 0x1ffffff]
 * Output Bounds:
 *   out1: [0x0 ~> 0x1ffffff]
 *   out2: [0x0 ~> 0x1]
 */
static void fiat_25519_addcarryx_u25(uint32_t *out1, uint8_t *out2,
				     uint8_t arg1, uint32_t arg2, uint32_t arg3)
{
	uint32_t x1 = ((arg1 + arg2) + arg3);
	uint32_t x2 = (x1 & UINT32_C(0x1ffffff));
	uint8_t x3 = (uint8_t)(x1 >> 25);
	*out1 = x2;
	*out2 = x3;
}

/*
 * The function fiat_25519_subborrowx_u25 is a subtraction with borrow.
 * Postconditions:
 *   out1 = (-arg1 + arg2 + -arg3) mod 2^25
 *   out2 = -⌊(-arg1 + arg2 + -arg3) / 2^25⌋
 *
 * Input Bounds:
 *   arg1: [0x0 ~> 0x1]
 *   arg2: [0x0 ~> 0x1ffffff]
 *   arg3: [0x0 ~> 0x1ffffff]
 * Output Bounds:
 *   out1: [0x0 ~> 0x1ffffff]
 *   out2: [0x0 ~> 0x1]
 */
static void fiat_25519_subborrowx_u25(uint32_t *out1, uint8_t *out2,
				      uint8_t arg1, uint32_t arg2,
				      uint32_t arg3)
{
	int32_t x1 = ((int32_t)(arg2 - arg1) - (int32_t)arg3);
	int8_t x2 = (int8_t)(x1 >> 25);
	uint32_t x3 = (x1 & UINT32_C(0x1ffffff));
	*out1 = x3;
	*out2 = (uint8_t)(0x0 - x2);
}

/*
 * The function fiat_25519_cmovznz_u32 is a single-word conditional move.
 * Postconditions:
 *   out1 = (if arg1 = 0 then arg2 else arg3)
 *
 * Input Bounds:
 *   arg1: [0x0 ~> 0x1]
 *   arg2: [0x0 ~> 0xffffffff]
 *   arg3: [0x0 ~> 0xffffffff]
 * Output Bounds:
 *   out1: [0x0 ~> 0xffffffff]
 */
static void fiat_25519_cmovznz_u32(uint32_t *out1, uint8_t arg1, uint32_t arg2,
				   uint32_t arg3)
{
	uint8_t x1 = (!(!arg1));
	uint32_t x2 = ((int8_t)(0x0 - x1) & UINT32_C(0xffffffff));
	// Note this line has been patched from the synthesized code to add value
	// barriers.
	//
	// Clang recognizes this pattern as a select. While it usually transforms it
	// to a cmov, it sometimes further transforms it into a branch, which we do
	// not want.
	uint32_t x3 = ((value_barrier_u32(x2) & arg3) |
		       (value_barrier_u32(~x2) & arg2));
	*out1 = x3;
}

/*
 * The function fiat_25519_carry_mul multiplies two field elements and reduces the result.
 * Postconditions:
 *   eval out1 mod m = (eval arg1 * eval arg2) mod m
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0xd333332], [0x0 ~> 0x6999999], [0x0 ~> 0xd333332], [0x0 ~> 0x6999999], [0x0 ~> 0xd333332], [0x0 ~> 0x6999999], [0x0 ~> 0xd333332], [0x0 ~> 0x6999999], [0x0 ~> 0xd333332], [0x0 ~> 0x6999999]]
 *   arg2: [[0x0 ~> 0xd333332], [0x0 ~> 0x6999999], [0x0 ~> 0xd333332], [0x0 ~> 0x6999999], [0x0 ~> 0xd333332], [0x0 ~> 0x6999999], [0x0 ~> 0xd333332], [0x0 ~> 0x6999999], [0x0 ~> 0xd333332], [0x0 ~> 0x6999999]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333]]
 */
static void fiat_25519_carry_mul(uint32_t out1[10], const uint32_t arg1[10],
				 const uint32_t arg2[10])
{
	uint64_t x1 = ((uint64_t)(arg1[9]) * ((arg2[9]) * UINT8_C(0x26)));
	uint64_t x2 = ((uint64_t)(arg1[9]) * ((arg2[8]) * UINT8_C(0x13)));
	uint64_t x3 = ((uint64_t)(arg1[9]) * ((arg2[7]) * UINT8_C(0x26)));
	uint64_t x4 = ((uint64_t)(arg1[9]) * ((arg2[6]) * UINT8_C(0x13)));
	uint64_t x5 = ((uint64_t)(arg1[9]) * ((arg2[5]) * UINT8_C(0x26)));
	uint64_t x6 = ((uint64_t)(arg1[9]) * ((arg2[4]) * UINT8_C(0x13)));
	uint64_t x7 = ((uint64_t)(arg1[9]) * ((arg2[3]) * UINT8_C(0x26)));
	uint64_t x8 = ((uint64_t)(arg1[9]) * ((arg2[2]) * UINT8_C(0x13)));
	uint64_t x9 = ((uint64_t)(arg1[9]) * ((arg2[1]) * UINT8_C(0x26)));
	uint64_t x10 = ((uint64_t)(arg1[8]) * ((arg2[9]) * UINT8_C(0x13)));
	uint64_t x11 = ((uint64_t)(arg1[8]) * ((arg2[8]) * UINT8_C(0x13)));
	uint64_t x12 = ((uint64_t)(arg1[8]) * ((arg2[7]) * UINT8_C(0x13)));
	uint64_t x13 = ((uint64_t)(arg1[8]) * ((arg2[6]) * UINT8_C(0x13)));
	uint64_t x14 = ((uint64_t)(arg1[8]) * ((arg2[5]) * UINT8_C(0x13)));
	uint64_t x15 = ((uint64_t)(arg1[8]) * ((arg2[4]) * UINT8_C(0x13)));
	uint64_t x16 = ((uint64_t)(arg1[8]) * ((arg2[3]) * UINT8_C(0x13)));
	uint64_t x17 = ((uint64_t)(arg1[8]) * ((arg2[2]) * UINT8_C(0x13)));
	uint64_t x18 = ((uint64_t)(arg1[7]) * ((arg2[9]) * UINT8_C(0x26)));
	uint64_t x19 = ((uint64_t)(arg1[7]) * ((arg2[8]) * UINT8_C(0x13)));
	uint64_t x20 = ((uint64_t)(arg1[7]) * ((arg2[7]) * UINT8_C(0x26)));
	uint64_t x21 = ((uint64_t)(arg1[7]) * ((arg2[6]) * UINT8_C(0x13)));
	uint64_t x22 = ((uint64_t)(arg1[7]) * ((arg2[5]) * UINT8_C(0x26)));
	uint64_t x23 = ((uint64_t)(arg1[7]) * ((arg2[4]) * UINT8_C(0x13)));
	uint64_t x24 = ((uint64_t)(arg1[7]) * ((arg2[3]) * UINT8_C(0x26)));
	uint64_t x25 = ((uint64_t)(arg1[6]) * ((arg2[9]) * UINT8_C(0x13)));
	uint64_t x26 = ((uint64_t)(arg1[6]) * ((arg2[8]) * UINT8_C(0x13)));
	uint64_t x27 = ((uint64_t)(arg1[6]) * ((arg2[7]) * UINT8_C(0x13)));
	uint64_t x28 = ((uint64_t)(arg1[6]) * ((arg2[6]) * UINT8_C(0x13)));
	uint64_t x29 = ((uint64_t)(arg1[6]) * ((arg2[5]) * UINT8_C(0x13)));
	uint64_t x30 = ((uint64_t)(arg1[6]) * ((arg2[4]) * UINT8_C(0x13)));
	uint64_t x31 = ((uint64_t)(arg1[5]) * ((arg2[9]) * UINT8_C(0x26)));
	uint64_t x32 = ((uint64_t)(arg1[5]) * ((arg2[8]) * UINT8_C(0x13)));
	uint64_t x33 = ((uint64_t)(arg1[5]) * ((arg2[7]) * UINT8_C(0x26)));
	uint64_t x34 = ((uint64_t)(arg1[5]) * ((arg2[6]) * UINT8_C(0x13)));
	uint64_t x35 = ((uint64_t)(arg1[5]) * ((arg2[5]) * UINT8_C(0x26)));
	uint64_t x36 = ((uint64_t)(arg1[4]) * ((arg2[9]) * UINT8_C(0x13)));
	uint64_t x37 = ((uint64_t)(arg1[4]) * ((arg2[8]) * UINT8_C(0x13)));
	uint64_t x38 = ((uint64_t)(arg1[4]) * ((arg2[7]) * UINT8_C(0x13)));
	uint64_t x39 = ((uint64_t)(arg1[4]) * ((arg2[6]) * UINT8_C(0x13)));
	uint64_t x40 = ((uint64_t)(arg1[3]) * ((arg2[9]) * UINT8_C(0x26)));
	uint64_t x41 = ((uint64_t)(arg1[3]) * ((arg2[8]) * UINT8_C(0x13)));
	uint64_t x42 = ((uint64_t)(arg1[3]) * ((arg2[7]) * UINT8_C(0x26)));
	uint64_t x43 = ((uint64_t)(arg1[2]) * ((arg2[9]) * UINT8_C(0x13)));
	uint64_t x44 = ((uint64_t)(arg1[2]) * ((arg2[8]) * UINT8_C(0x13)));
	uint64_t x45 = ((uint64_t)(arg1[1]) * ((arg2[9]) * UINT8_C(0x26)));
	uint64_t x46 = ((uint64_t)(arg1[9]) * (arg2[0]));
	uint64_t x47 = ((uint64_t)(arg1[8]) * (arg2[1]));
	uint64_t x48 = ((uint64_t)(arg1[8]) * (arg2[0]));
	uint64_t x49 = ((uint64_t)(arg1[7]) * (arg2[2]));
	uint64_t x50 = ((uint64_t)(arg1[7]) * ((arg2[1]) * 0x2));
	uint64_t x51 = ((uint64_t)(arg1[7]) * (arg2[0]));
	uint64_t x52 = ((uint64_t)(arg1[6]) * (arg2[3]));
	uint64_t x53 = ((uint64_t)(arg1[6]) * (arg2[2]));
	uint64_t x54 = ((uint64_t)(arg1[6]) * (arg2[1]));
	uint64_t x55 = ((uint64_t)(arg1[6]) * (arg2[0]));
	uint64_t x56 = ((uint64_t)(arg1[5]) * (arg2[4]));
	uint64_t x57 = ((uint64_t)(arg1[5]) * ((arg2[3]) * 0x2));
	uint64_t x58 = ((uint64_t)(arg1[5]) * (arg2[2]));
	uint64_t x59 = ((uint64_t)(arg1[5]) * ((arg2[1]) * 0x2));
	uint64_t x60 = ((uint64_t)(arg1[5]) * (arg2[0]));
	uint64_t x61 = ((uint64_t)(arg1[4]) * (arg2[5]));
	uint64_t x62 = ((uint64_t)(arg1[4]) * (arg2[4]));
	uint64_t x63 = ((uint64_t)(arg1[4]) * (arg2[3]));
	uint64_t x64 = ((uint64_t)(arg1[4]) * (arg2[2]));
	uint64_t x65 = ((uint64_t)(arg1[4]) * (arg2[1]));
	uint64_t x66 = ((uint64_t)(arg1[4]) * (arg2[0]));
	uint64_t x67 = ((uint64_t)(arg1[3]) * (arg2[6]));
	uint64_t x68 = ((uint64_t)(arg1[3]) * ((arg2[5]) * 0x2));
	uint64_t x69 = ((uint64_t)(arg1[3]) * (arg2[4]));
	uint64_t x70 = ((uint64_t)(arg1[3]) * ((arg2[3]) * 0x2));
	uint64_t x71 = ((uint64_t)(arg1[3]) * (arg2[2]));
	uint64_t x72 = ((uint64_t)(arg1[3]) * ((arg2[1]) * 0x2));
	uint64_t x73 = ((uint64_t)(arg1[3]) * (arg2[0]));
	uint64_t x74 = ((uint64_t)(arg1[2]) * (arg2[7]));
	uint64_t x75 = ((uint64_t)(arg1[2]) * (arg2[6]));
	uint64_t x76 = ((uint64_t)(arg1[2]) * (arg2[5]));
	uint64_t x77 = ((uint64_t)(arg1[2]) * (arg2[4]));
	uint64_t x78 = ((uint64_t)(arg1[2]) * (arg2[3]));
	uint64_t x79 = ((uint64_t)(arg1[2]) * (arg2[2]));
	uint64_t x80 = ((uint64_t)(arg1[2]) * (arg2[1]));
	uint64_t x81 = ((uint64_t)(arg1[2]) * (arg2[0]));
	uint64_t x82 = ((uint64_t)(arg1[1]) * (arg2[8]));
	uint64_t x83 = ((uint64_t)(arg1[1]) * ((arg2[7]) * 0x2));
	uint64_t x84 = ((uint64_t)(arg1[1]) * (arg2[6]));
	uint64_t x85 = ((uint64_t)(arg1[1]) * ((arg2[5]) * 0x2));
	uint64_t x86 = ((uint64_t)(arg1[1]) * (arg2[4]));
	uint64_t x87 = ((uint64_t)(arg1[1]) * ((arg2[3]) * 0x2));
	uint64_t x88 = ((uint64_t)(arg1[1]) * (arg2[2]));
	uint64_t x89 = ((uint64_t)(arg1[1]) * ((arg2[1]) * 0x2));
	uint64_t x90 = ((uint64_t)(arg1[1]) * (arg2[0]));
	uint64_t x91 = ((uint64_t)(arg1[0]) * (arg2[9]));
	uint64_t x92 = ((uint64_t)(arg1[0]) * (arg2[8]));
	uint64_t x93 = ((uint64_t)(arg1[0]) * (arg2[7]));
	uint64_t x94 = ((uint64_t)(arg1[0]) * (arg2[6]));
	uint64_t x95 = ((uint64_t)(arg1[0]) * (arg2[5]));
	uint64_t x96 = ((uint64_t)(arg1[0]) * (arg2[4]));
	uint64_t x97 = ((uint64_t)(arg1[0]) * (arg2[3]));
	uint64_t x98 = ((uint64_t)(arg1[0]) * (arg2[2]));
	uint64_t x99 = ((uint64_t)(arg1[0]) * (arg2[1]));
	uint64_t x100 = ((uint64_t)(arg1[0]) * (arg2[0]));
	uint64_t x101 =
		(x100 +
		 (x45 +
		  (x44 + (x42 + (x39 + (x35 + (x30 + (x24 + (x17 + x9)))))))));
	uint64_t x102 = (x101 >> 26);
	uint32_t x103 = (uint32_t)(x101 & UINT32_C(0x3ffffff));
	uint64_t x104 =
		(x91 +
		 (x82 +
		  (x74 + (x67 + (x61 + (x56 + (x52 + (x49 + (x47 + x46)))))))));
	uint64_t x105 =
		(x92 +
		 (x83 +
		  (x75 + (x68 + (x62 + (x57 + (x53 + (x50 + (x48 + x1)))))))));
	uint64_t x106 =
		(x93 +
		 (x84 +
		  (x76 + (x69 + (x63 + (x58 + (x54 + (x51 + (x10 + x2)))))))));
	uint64_t x107 =
		(x94 +
		 (x85 +
		  (x77 + (x70 + (x64 + (x59 + (x55 + (x18 + (x11 + x3)))))))));
	uint64_t x108 =
		(x95 +
		 (x86 +
		  (x78 + (x71 + (x65 + (x60 + (x25 + (x19 + (x12 + x4)))))))));
	uint64_t x109 =
		(x96 +
		 (x87 +
		  (x79 + (x72 + (x66 + (x31 + (x26 + (x20 + (x13 + x5)))))))));
	uint64_t x110 =
		(x97 +
		 (x88 +
		  (x80 + (x73 + (x36 + (x32 + (x27 + (x21 + (x14 + x6)))))))));
	uint64_t x111 =
		(x98 +
		 (x89 +
		  (x81 + (x40 + (x37 + (x33 + (x28 + (x22 + (x15 + x7)))))))));
	uint64_t x112 =
		(x99 +
		 (x90 +
		  (x43 + (x41 + (x38 + (x34 + (x29 + (x23 + (x16 + x8)))))))));
	uint64_t x113 = (x102 + x112);
	uint64_t x114 = (x113 >> 25);
	uint32_t x115 = (uint32_t)(x113 & UINT32_C(0x1ffffff));
	uint64_t x116 = (x114 + x111);
	uint64_t x117 = (x116 >> 26);
	uint32_t x118 = (uint32_t)(x116 & UINT32_C(0x3ffffff));
	uint64_t x119 = (x117 + x110);
	uint64_t x120 = (x119 >> 25);
	uint32_t x121 = (uint32_t)(x119 & UINT32_C(0x1ffffff));
	uint64_t x122 = (x120 + x109);
	uint64_t x123 = (x122 >> 26);
	uint32_t x124 = (uint32_t)(x122 & UINT32_C(0x3ffffff));
	uint64_t x125 = (x123 + x108);
	uint64_t x126 = (x125 >> 25);
	uint32_t x127 = (uint32_t)(x125 & UINT32_C(0x1ffffff));
	uint64_t x128 = (x126 + x107);
	uint64_t x129 = (x128 >> 26);
	uint32_t x130 = (uint32_t)(x128 & UINT32_C(0x3ffffff));
	uint64_t x131 = (x129 + x106);
	uint64_t x132 = (x131 >> 25);
	uint32_t x133 = (uint32_t)(x131 & UINT32_C(0x1ffffff));
	uint64_t x134 = (x132 + x105);
	uint64_t x135 = (x134 >> 26);
	uint32_t x136 = (uint32_t)(x134 & UINT32_C(0x3ffffff));
	uint64_t x137 = (x135 + x104);
	uint64_t x138 = (x137 >> 25);
	uint32_t x139 = (uint32_t)(x137 & UINT32_C(0x1ffffff));
	uint64_t x140 = (x138 * UINT8_C(0x13));
	uint64_t x141 = (x103 + x140);
	uint32_t x142 = (uint32_t)(x141 >> 26);
	uint32_t x143 = (uint32_t)(x141 & UINT32_C(0x3ffffff));
	uint32_t x144 = (x142 + x115);
	uint8_t x145 = (uint8_t)(x144 >> 25);
	uint32_t x146 = (x144 & UINT32_C(0x1ffffff));
	uint32_t x147 = (x145 + x118);
	out1[0] = x143;
	out1[1] = x146;
	out1[2] = x147;
	out1[3] = x121;
	out1[4] = x124;
	out1[5] = x127;
	out1[6] = x130;
	out1[7] = x133;
	out1[8] = x136;
	out1[9] = x139;
}

/*
 * The function fiat_25519_carry_square squares a field element and reduces the result.
 * Postconditions:
 *   eval out1 mod m = (eval arg1 * eval arg1) mod m
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0xd333332], [0x0 ~> 0x6999999], [0x0 ~> 0xd333332], [0x0 ~> 0x6999999], [0x0 ~> 0xd333332], [0x0 ~> 0x6999999], [0x0 ~> 0xd333332], [0x0 ~> 0x6999999], [0x0 ~> 0xd333332], [0x0 ~> 0x6999999]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333]]
 */
static void fiat_25519_carry_square(uint32_t out1[10], const uint32_t arg1[10])
{
	uint32_t x1 = ((arg1[9]) * UINT8_C(0x13));
	uint32_t x2 = (x1 * 0x2);
	uint32_t x3 = ((arg1[9]) * 0x2);
	uint32_t x4 = ((arg1[8]) * UINT8_C(0x13));
	uint64_t x5 = ((uint64_t)x4 * 0x2);
	uint32_t x6 = ((arg1[8]) * 0x2);
	uint32_t x7 = ((arg1[7]) * UINT8_C(0x13));
	uint32_t x8 = (x7 * 0x2);
	uint32_t x9 = ((arg1[7]) * 0x2);
	uint32_t x10 = ((arg1[6]) * UINT8_C(0x13));
	uint64_t x11 = ((uint64_t)x10 * 0x2);
	uint32_t x12 = ((arg1[6]) * 0x2);
	uint32_t x13 = ((arg1[5]) * UINT8_C(0x13));
	uint32_t x14 = ((arg1[5]) * 0x2);
	uint32_t x15 = ((arg1[4]) * 0x2);
	uint32_t x16 = ((arg1[3]) * 0x2);
	uint32_t x17 = ((arg1[2]) * 0x2);
	uint32_t x18 = ((arg1[1]) * 0x2);
	uint64_t x19 = ((uint64_t)(arg1[9]) * (x1 * 0x2));
	uint64_t x20 = ((uint64_t)(arg1[8]) * x2);
	uint64_t x21 = ((uint64_t)(arg1[8]) * x4);
	uint64_t x22 = ((arg1[7]) * ((uint64_t)x2 * 0x2));
	uint64_t x23 = ((arg1[7]) * x5);
	uint64_t x24 = ((uint64_t)(arg1[7]) * (x7 * 0x2));
	uint64_t x25 = ((uint64_t)(arg1[6]) * x2);
	uint64_t x26 = ((arg1[6]) * x5);
	uint64_t x27 = ((uint64_t)(arg1[6]) * x8);
	uint64_t x28 = ((uint64_t)(arg1[6]) * x10);
	uint64_t x29 = ((arg1[5]) * ((uint64_t)x2 * 0x2));
	uint64_t x30 = ((arg1[5]) * x5);
	uint64_t x31 = ((arg1[5]) * ((uint64_t)x8 * 0x2));
	uint64_t x32 = ((arg1[5]) * x11);
	uint64_t x33 = ((uint64_t)(arg1[5]) * (x13 * 0x2));
	uint64_t x34 = ((uint64_t)(arg1[4]) * x2);
	uint64_t x35 = ((arg1[4]) * x5);
	uint64_t x36 = ((uint64_t)(arg1[4]) * x8);
	uint64_t x37 = ((arg1[4]) * x11);
	uint64_t x38 = ((uint64_t)(arg1[4]) * x14);
	uint64_t x39 = ((uint64_t)(arg1[4]) * (arg1[4]));
	uint64_t x40 = ((arg1[3]) * ((uint64_t)x2 * 0x2));
	uint64_t x41 = ((arg1[3]) * x5);
	uint64_t x42 = ((arg1[3]) * ((uint64_t)x8 * 0x2));
	uint64_t x43 = ((uint64_t)(arg1[3]) * x12);
	uint64_t x44 = ((uint64_t)(arg1[3]) * (x14 * 0x2));
	uint64_t x45 = ((uint64_t)(arg1[3]) * x15);
	uint64_t x46 = ((uint64_t)(arg1[3]) * ((arg1[3]) * 0x2));
	uint64_t x47 = ((uint64_t)(arg1[2]) * x2);
	uint64_t x48 = ((arg1[2]) * x5);
	uint64_t x49 = ((uint64_t)(arg1[2]) * x9);
	uint64_t x50 = ((uint64_t)(arg1[2]) * x12);
	uint64_t x51 = ((uint64_t)(arg1[2]) * x14);
	uint64_t x52 = ((uint64_t)(arg1[2]) * x15);
	uint64_t x53 = ((uint64_t)(arg1[2]) * x16);
	uint64_t x54 = ((uint64_t)(arg1[2]) * (arg1[2]));
	uint64_t x55 = ((arg1[1]) * ((uint64_t)x2 * 0x2));
	uint64_t x56 = ((uint64_t)(arg1[1]) * x6);
	uint64_t x57 = ((uint64_t)(arg1[1]) * (x9 * 0x2));
	uint64_t x58 = ((uint64_t)(arg1[1]) * x12);
	uint64_t x59 = ((uint64_t)(arg1[1]) * (x14 * 0x2));
	uint64_t x60 = ((uint64_t)(arg1[1]) * x15);
	uint64_t x61 = ((uint64_t)(arg1[1]) * (x16 * 0x2));
	uint64_t x62 = ((uint64_t)(arg1[1]) * x17);
	uint64_t x63 = ((uint64_t)(arg1[1]) * ((arg1[1]) * 0x2));
	uint64_t x64 = ((uint64_t)(arg1[0]) * x3);
	uint64_t x65 = ((uint64_t)(arg1[0]) * x6);
	uint64_t x66 = ((uint64_t)(arg1[0]) * x9);
	uint64_t x67 = ((uint64_t)(arg1[0]) * x12);
	uint64_t x68 = ((uint64_t)(arg1[0]) * x14);
	uint64_t x69 = ((uint64_t)(arg1[0]) * x15);
	uint64_t x70 = ((uint64_t)(arg1[0]) * x16);
	uint64_t x71 = ((uint64_t)(arg1[0]) * x17);
	uint64_t x72 = ((uint64_t)(arg1[0]) * x18);
	uint64_t x73 = ((uint64_t)(arg1[0]) * (arg1[0]));
	uint64_t x74 = (x73 + (x55 + (x48 + (x42 + (x37 + x33)))));
	uint64_t x75 = (x74 >> 26);
	uint32_t x76 = (uint32_t)(x74 & UINT32_C(0x3ffffff));
	uint64_t x77 = (x64 + (x56 + (x49 + (x43 + x38))));
	uint64_t x78 = (x65 + (x57 + (x50 + (x44 + (x39 + x19)))));
	uint64_t x79 = (x66 + (x58 + (x51 + (x45 + x20))));
	uint64_t x80 = (x67 + (x59 + (x52 + (x46 + (x22 + x21)))));
	uint64_t x81 = (x68 + (x60 + (x53 + (x25 + x23))));
	uint64_t x82 = (x69 + (x61 + (x54 + (x29 + (x26 + x24)))));
	uint64_t x83 = (x70 + (x62 + (x34 + (x30 + x27))));
	uint64_t x84 = (x71 + (x63 + (x40 + (x35 + (x31 + x28)))));
	uint64_t x85 = (x72 + (x47 + (x41 + (x36 + x32))));
	uint64_t x86 = (x75 + x85);
	uint64_t x87 = (x86 >> 25);
	uint32_t x88 = (uint32_t)(x86 & UINT32_C(0x1ffffff));
	uint64_t x89 = (x87 + x84);
	uint64_t x90 = (x89 >> 26);
	uint32_t x91 = (uint32_t)(x89 & UINT32_C(0x3ffffff));
	uint64_t x92 = (x90 + x83);
	uint64_t x93 = (x92 >> 25);
	uint32_t x94 = (uint32_t)(x92 & UINT32_C(0x1ffffff));
	uint64_t x95 = (x93 + x82);
	uint64_t x96 = (x95 >> 26);
	uint32_t x97 = (uint32_t)(x95 & UINT32_C(0x3ffffff));
	uint64_t x98 = (x96 + x81);
	uint64_t x99 = (x98 >> 25);
	uint32_t x100 = (uint32_t)(x98 & UINT32_C(0x1ffffff));
	uint64_t x101 = (x99 + x80);
	uint64_t x102 = (x101 >> 26);
	uint32_t x103 = (uint32_t)(x101 & UINT32_C(0x3ffffff));
	uint64_t x104 = (x102 + x79);
	uint64_t x105 = (x104 >> 25);
	uint32_t x106 = (uint32_t)(x104 & UINT32_C(0x1ffffff));
	uint64_t x107 = (x105 + x78);
	uint64_t x108 = (x107 >> 26);
	uint32_t x109 = (uint32_t)(x107 & UINT32_C(0x3ffffff));
	uint64_t x110 = (x108 + x77);
	uint64_t x111 = (x110 >> 25);
	uint32_t x112 = (uint32_t)(x110 & UINT32_C(0x1ffffff));
	uint64_t x113 = (x111 * UINT8_C(0x13));
	uint64_t x114 = (x76 + x113);
	uint32_t x115 = (uint32_t)(x114 >> 26);
	uint32_t x116 = (uint32_t)(x114 & UINT32_C(0x3ffffff));
	uint32_t x117 = (x115 + x88);
	uint8_t x118 = (uint8_t)(x117 >> 25);
	uint32_t x119 = (x117 & UINT32_C(0x1ffffff));
	uint32_t x120 = (x118 + x91);
	out1[0] = x116;
	out1[1] = x119;
	out1[2] = x120;
	out1[3] = x94;
	out1[4] = x97;
	out1[5] = x100;
	out1[6] = x103;
	out1[7] = x106;
	out1[8] = x109;
	out1[9] = x112;
}

/*
 * The function fiat_25519_carry reduces a field element.
 * Postconditions:
 *   eval out1 mod m = eval arg1 mod m
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0xd333332], [0x0 ~> 0x6999999], [0x0 ~> 0xd333332], [0x0 ~> 0x6999999], [0x0 ~> 0xd333332], [0x0 ~> 0x6999999], [0x0 ~> 0xd333332], [0x0 ~> 0x6999999], [0x0 ~> 0xd333332], [0x0 ~> 0x6999999]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333]]
 */
static void fiat_25519_carry(uint32_t out1[10], const uint32_t arg1[10])
{
	uint32_t x1 = (arg1[0]);
	uint32_t x2 = ((x1 >> 26) + (arg1[1]));
	uint32_t x3 = ((x2 >> 25) + (arg1[2]));
	uint32_t x4 = ((x3 >> 26) + (arg1[3]));
	uint32_t x5 = ((x4 >> 25) + (arg1[4]));
	uint32_t x6 = ((x5 >> 26) + (arg1[5]));
	uint32_t x7 = ((x6 >> 25) + (arg1[6]));
	uint32_t x8 = ((x7 >> 26) + (arg1[7]));
	uint32_t x9 = ((x8 >> 25) + (arg1[8]));
	uint32_t x10 = ((x9 >> 26) + (arg1[9]));
	uint32_t x11 =
		((x1 & UINT32_C(0x3ffffff)) + ((x10 >> 25) * UINT8_C(0x13)));
	uint32_t x12 = ((uint8_t)(x11 >> 26) + (x2 & UINT32_C(0x1ffffff)));
	uint32_t x13 = (x11 & UINT32_C(0x3ffffff));
	uint32_t x14 = (x12 & UINT32_C(0x1ffffff));
	uint32_t x15 = ((uint8_t)(x12 >> 25) + (x3 & UINT32_C(0x3ffffff)));
	uint32_t x16 = (x4 & UINT32_C(0x1ffffff));
	uint32_t x17 = (x5 & UINT32_C(0x3ffffff));
	uint32_t x18 = (x6 & UINT32_C(0x1ffffff));
	uint32_t x19 = (x7 & UINT32_C(0x3ffffff));
	uint32_t x20 = (x8 & UINT32_C(0x1ffffff));
	uint32_t x21 = (x9 & UINT32_C(0x3ffffff));
	uint32_t x22 = (x10 & UINT32_C(0x1ffffff));
	out1[0] = x13;
	out1[1] = x14;
	out1[2] = x15;
	out1[3] = x16;
	out1[4] = x17;
	out1[5] = x18;
	out1[6] = x19;
	out1[7] = x20;
	out1[8] = x21;
	out1[9] = x22;
}

/*
 * The function fiat_25519_add adds two field elements.
 * Postconditions:
 *   eval out1 mod m = (eval arg1 + eval arg2) mod m
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333]]
 *   arg2: [[0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0xd333332], [0x0 ~> 0x6999999], [0x0 ~> 0xd333332], [0x0 ~> 0x6999999], [0x0 ~> 0xd333332], [0x0 ~> 0x6999999], [0x0 ~> 0xd333332], [0x0 ~> 0x6999999], [0x0 ~> 0xd333332], [0x0 ~> 0x6999999]]
 */
static void fiat_25519_add(uint32_t out1[10], const uint32_t arg1[10],
			   const uint32_t arg2[10])
{
	uint32_t x1 = ((arg1[0]) + (arg2[0]));
	uint32_t x2 = ((arg1[1]) + (arg2[1]));
	uint32_t x3 = ((arg1[2]) + (arg2[2]));
	uint32_t x4 = ((arg1[3]) + (arg2[3]));
	uint32_t x5 = ((arg1[4]) + (arg2[4]));
	uint32_t x6 = ((arg1[5]) + (arg2[5]));
	uint32_t x7 = ((arg1[6]) + (arg2[6]));
	uint32_t x8 = ((arg1[7]) + (arg2[7]));
	uint32_t x9 = ((arg1[8]) + (arg2[8]));
	uint32_t x10 = ((arg1[9]) + (arg2[9]));
	out1[0] = x1;
	out1[1] = x2;
	out1[2] = x3;
	out1[3] = x4;
	out1[4] = x5;
	out1[5] = x6;
	out1[6] = x7;
	out1[7] = x8;
	out1[8] = x9;
	out1[9] = x10;
}

/*
 * The function fiat_25519_sub subtracts two field elements.
 * Postconditions:
 *   eval out1 mod m = (eval arg1 - eval arg2) mod m
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333]]
 *   arg2: [[0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0xd333332], [0x0 ~> 0x6999999], [0x0 ~> 0xd333332], [0x0 ~> 0x6999999], [0x0 ~> 0xd333332], [0x0 ~> 0x6999999], [0x0 ~> 0xd333332], [0x0 ~> 0x6999999], [0x0 ~> 0xd333332], [0x0 ~> 0x6999999]]
 */
static void fiat_25519_sub(uint32_t out1[10], const uint32_t arg1[10],
			   const uint32_t arg2[10])
{
	uint32_t x1 = ((UINT32_C(0x7ffffda) + (arg1[0])) - (arg2[0]));
	uint32_t x2 = ((UINT32_C(0x3fffffe) + (arg1[1])) - (arg2[1]));
	uint32_t x3 = ((UINT32_C(0x7fffffe) + (arg1[2])) - (arg2[2]));
	uint32_t x4 = ((UINT32_C(0x3fffffe) + (arg1[3])) - (arg2[3]));
	uint32_t x5 = ((UINT32_C(0x7fffffe) + (arg1[4])) - (arg2[4]));
	uint32_t x6 = ((UINT32_C(0x3fffffe) + (arg1[5])) - (arg2[5]));
	uint32_t x7 = ((UINT32_C(0x7fffffe) + (arg1[6])) - (arg2[6]));
	uint32_t x8 = ((UINT32_C(0x3fffffe) + (arg1[7])) - (arg2[7]));
	uint32_t x9 = ((UINT32_C(0x7fffffe) + (arg1[8])) - (arg2[8]));
	uint32_t x10 = ((UINT32_C(0x3fffffe) + (arg1[9])) - (arg2[9]));
	out1[0] = x1;
	out1[1] = x2;
	out1[2] = x3;
	out1[3] = x4;
	out1[4] = x5;
	out1[5] = x6;
	out1[6] = x7;
	out1[7] = x8;
	out1[8] = x9;
	out1[9] = x10;
}

/*
 * The function fiat_25519_opp negates a field element.
 * Postconditions:
 *   eval out1 mod m = -eval arg1 mod m
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0xd333332], [0x0 ~> 0x6999999], [0x0 ~> 0xd333332], [0x0 ~> 0x6999999], [0x0 ~> 0xd333332], [0x0 ~> 0x6999999], [0x0 ~> 0xd333332], [0x0 ~> 0x6999999], [0x0 ~> 0xd333332], [0x0 ~> 0x6999999]]
 */
static void fiat_25519_opp(uint32_t out1[10], const uint32_t arg1[10])
{
	uint32_t x1 = (UINT32_C(0x7ffffda) - (arg1[0]));
	uint32_t x2 = (UINT32_C(0x3fffffe) - (arg1[1]));
	uint32_t x3 = (UINT32_C(0x7fffffe) - (arg1[2]));
	uint32_t x4 = (UINT32_C(0x3fffffe) - (arg1[3]));
	uint32_t x5 = (UINT32_C(0x7fffffe) - (arg1[4]));
	uint32_t x6 = (UINT32_C(0x3fffffe) - (arg1[5]));
	uint32_t x7 = (UINT32_C(0x7fffffe) - (arg1[6]));
	uint32_t x8 = (UINT32_C(0x3fffffe) - (arg1[7]));
	uint32_t x9 = (UINT32_C(0x7fffffe) - (arg1[8]));
	uint32_t x10 = (UINT32_C(0x3fffffe) - (arg1[9]));
	out1[0] = x1;
	out1[1] = x2;
	out1[2] = x3;
	out1[3] = x4;
	out1[4] = x5;
	out1[5] = x6;
	out1[6] = x7;
	out1[7] = x8;
	out1[8] = x9;
	out1[9] = x10;
}

/*
 * The function fiat_25519_to_bytes serializes a field element to bytes in little-endian order.
 * Postconditions:
 *   out1 = map (λ x, ⌊((eval arg1 mod m) mod 2^(8 * (x + 1))) / 2^(8 * x)⌋) [0..31]
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0x7f]]
 */
static void fiat_25519_to_bytes(uint8_t out1[32], const uint32_t arg1[10])
{
	uint32_t x1;
	uint8_t x2;
	fiat_25519_subborrowx_u26(&x1, &x2, 0x0, (arg1[0]),
				  UINT32_C(0x3ffffed));
	uint32_t x3;
	uint8_t x4;
	fiat_25519_subborrowx_u25(&x3, &x4, x2, (arg1[1]), UINT32_C(0x1ffffff));
	uint32_t x5;
	uint8_t x6;
	fiat_25519_subborrowx_u26(&x5, &x6, x4, (arg1[2]), UINT32_C(0x3ffffff));
	uint32_t x7;
	uint8_t x8;
	fiat_25519_subborrowx_u25(&x7, &x8, x6, (arg1[3]), UINT32_C(0x1ffffff));
	uint32_t x9;
	uint8_t x10;
	fiat_25519_subborrowx_u26(&x9, &x10, x8, (arg1[4]),
				  UINT32_C(0x3ffffff));
	uint32_t x11;
	uint8_t x12;
	fiat_25519_subborrowx_u25(&x11, &x12, x10, (arg1[5]),
				  UINT32_C(0x1ffffff));
	uint32_t x13;
	uint8_t x14;
	fiat_25519_subborrowx_u26(&x13, &x14, x12, (arg1[6]),
				  UINT32_C(0x3ffffff));
	uint32_t x15;
	uint8_t x16;
	fiat_25519_subborrowx_u25(&x15, &x16, x14, (arg1[7]),
				  UINT32_C(0x1ffffff));
	uint32_t x17;
	uint8_t x18;
	fiat_25519_subborrowx_u26(&x17, &x18, x16, (arg1[8]),
				  UINT32_C(0x3ffffff));
	uint32_t x19;
	uint8_t x20;
	fiat_25519_subborrowx_u25(&x19, &x20, x18, (arg1[9]),
				  UINT32_C(0x1ffffff));
	uint32_t x21;
	fiat_25519_cmovznz_u32(&x21, x20, 0x0, UINT32_C(0xffffffff));
	uint32_t x22;
	uint8_t x23;
	fiat_25519_addcarryx_u26(&x22, &x23, 0x0, x1,
				 (x21 & UINT32_C(0x3ffffed)));
	uint32_t x24;
	uint8_t x25;
	fiat_25519_addcarryx_u25(&x24, &x25, x23, x3,
				 (x21 & UINT32_C(0x1ffffff)));
	uint32_t x26;
	uint8_t x27;
	fiat_25519_addcarryx_u26(&x26, &x27, x25, x5,
				 (x21 & UINT32_C(0x3ffffff)));
	uint32_t x28;
	uint8_t x29;
	fiat_25519_addcarryx_u25(&x28, &x29, x27, x7,
				 (x21 & UINT32_C(0x1ffffff)));
	uint32_t x30;
	uint8_t x31;
	fiat_25519_addcarryx_u26(&x30, &x31, x29, x9,
				 (x21 & UINT32_C(0x3ffffff)));
	uint32_t x32;
	uint8_t x33;
	fiat_25519_addcarryx_u25(&x32, &x33, x31, x11,
				 (x21 & UINT32_C(0x1ffffff)));
	uint32_t x34;
	uint8_t x35;
	fiat_25519_addcarryx_u26(&x34, &x35, x33, x13,
				 (x21 & UINT32_C(0x3ffffff)));
	uint32_t x36;
	uint8_t x37;
	fiat_25519_addcarryx_u25(&x36, &x37, x35, x15,
				 (x21 & UINT32_C(0x1ffffff)));
	uint32_t x38;
	uint8_t x39;
	fiat_25519_addcarryx_u26(&x38, &x39, x37, x17,
				 (x21 & UINT32_C(0x3ffffff)));
	uint32_t x40;
	uint8_t x41;
	fiat_25519_addcarryx_u25(&x40, &x41, x39, x19,
				 (x21 & UINT32_C(0x1ffffff)));
	uint32_t x42 = (x40 << 6);
	uint32_t x43 = (x38 << 4);
	uint32_t x44 = (x36 << 3);
	uint32_t x45 = (x34 * (uint32_t)0x2);
	uint32_t x46 = (x30 << 6);
	uint32_t x47 = (x28 << 5);
	uint32_t x48 = (x26 << 3);
	uint32_t x49 = (x24 << 2);
	uint32_t x50 = (x22 >> 8);
	uint8_t x51 = (uint8_t)(x22 & UINT8_C(0xff));
	uint32_t x52 = (x50 >> 8);
	uint8_t x53 = (uint8_t)(x50 & UINT8_C(0xff));
	uint8_t x54 = (uint8_t)(x52 >> 8);
	uint8_t x55 = (uint8_t)(x52 & UINT8_C(0xff));
	uint32_t x56 = (x54 + x49);
	uint32_t x57 = (x56 >> 8);
	uint8_t x58 = (uint8_t)(x56 & UINT8_C(0xff));
	uint32_t x59 = (x57 >> 8);
	uint8_t x60 = (uint8_t)(x57 & UINT8_C(0xff));
	uint8_t x61 = (uint8_t)(x59 >> 8);
	uint8_t x62 = (uint8_t)(x59 & UINT8_C(0xff));
	uint32_t x63 = (x61 + x48);
	uint32_t x64 = (x63 >> 8);
	uint8_t x65 = (uint8_t)(x63 & UINT8_C(0xff));
	uint32_t x66 = (x64 >> 8);
	uint8_t x67 = (uint8_t)(x64 & UINT8_C(0xff));
	uint8_t x68 = (uint8_t)(x66 >> 8);
	uint8_t x69 = (uint8_t)(x66 & UINT8_C(0xff));
	uint32_t x70 = (x68 + x47);
	uint32_t x71 = (x70 >> 8);
	uint8_t x72 = (uint8_t)(x70 & UINT8_C(0xff));
	uint32_t x73 = (x71 >> 8);
	uint8_t x74 = (uint8_t)(x71 & UINT8_C(0xff));
	uint8_t x75 = (uint8_t)(x73 >> 8);
	uint8_t x76 = (uint8_t)(x73 & UINT8_C(0xff));
	uint32_t x77 = (x75 + x46);
	uint32_t x78 = (x77 >> 8);
	uint8_t x79 = (uint8_t)(x77 & UINT8_C(0xff));
	uint32_t x80 = (x78 >> 8);
	uint8_t x81 = (uint8_t)(x78 & UINT8_C(0xff));
	uint8_t x82 = (uint8_t)(x80 >> 8);
	uint8_t x83 = (uint8_t)(x80 & UINT8_C(0xff));
	uint8_t x84 = (uint8_t)(x82 & UINT8_C(0xff));
	uint32_t x85 = (x32 >> 8);
	uint8_t x86 = (uint8_t)(x32 & UINT8_C(0xff));
	uint32_t x87 = (x85 >> 8);
	uint8_t x88 = (uint8_t)(x85 & UINT8_C(0xff));
	uint8_t x89 = (uint8_t)(x87 >> 8);
	uint8_t x90 = (uint8_t)(x87 & UINT8_C(0xff));
	uint32_t x91 = (x89 + x45);
	uint32_t x92 = (x91 >> 8);
	uint8_t x93 = (uint8_t)(x91 & UINT8_C(0xff));
	uint32_t x94 = (x92 >> 8);
	uint8_t x95 = (uint8_t)(x92 & UINT8_C(0xff));
	uint8_t x96 = (uint8_t)(x94 >> 8);
	uint8_t x97 = (uint8_t)(x94 & UINT8_C(0xff));
	uint32_t x98 = (x96 + x44);
	uint32_t x99 = (x98 >> 8);
	uint8_t x100 = (uint8_t)(x98 & UINT8_C(0xff));
	uint32_t x101 = (x99 >> 8);
	uint8_t x102 = (uint8_t)(x99 & UINT8_C(0xff));
	uint8_t x103 = (uint8_t)(x101 >> 8);
	uint8_t x104 = (uint8_t)(x101 & UINT8_C(0xff));
	uint32_t x105 = (x103 + x43);
	uint32_t x106 = (x105 >> 8);
	uint8_t x107 = (uint8_t)(x105 & UINT8_C(0xff));
	uint32_t x108 = (x106 >> 8);
	uint8_t x109 = (uint8_t)(x106 & UINT8_C(0xff));
	uint8_t x110 = (uint8_t)(x108 >> 8);
	uint8_t x111 = (uint8_t)(x108 & UINT8_C(0xff));
	uint32_t x112 = (x110 + x42);
	uint32_t x113 = (x112 >> 8);
	uint8_t x114 = (uint8_t)(x112 & UINT8_C(0xff));
	uint32_t x115 = (x113 >> 8);
	uint8_t x116 = (uint8_t)(x113 & UINT8_C(0xff));
	uint8_t x117 = (uint8_t)(x115 >> 8);
	uint8_t x118 = (uint8_t)(x115 & UINT8_C(0xff));
	out1[0] = x51;
	out1[1] = x53;
	out1[2] = x55;
	out1[3] = x58;
	out1[4] = x60;
	out1[5] = x62;
	out1[6] = x65;
	out1[7] = x67;
	out1[8] = x69;
	out1[9] = x72;
	out1[10] = x74;
	out1[11] = x76;
	out1[12] = x79;
	out1[13] = x81;
	out1[14] = x83;
	out1[15] = x84;
	out1[16] = x86;
	out1[17] = x88;
	out1[18] = x90;
	out1[19] = x93;
	out1[20] = x95;
	out1[21] = x97;
	out1[22] = x100;
	out1[23] = x102;
	out1[24] = x104;
	out1[25] = x107;
	out1[26] = x109;
	out1[27] = x111;
	out1[28] = x114;
	out1[29] = x116;
	out1[30] = x118;
	out1[31] = x117;
}

/*
 * The function fiat_25519_from_bytes deserializes a field element from bytes in little-endian order.
 * Postconditions:
 *   eval out1 mod m = bytes_eval arg1 mod m
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0x7f]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333], [0x0 ~> 0x4666666], [0x0 ~> 0x2333333]]
 */
static void fiat_25519_from_bytes(uint32_t out1[10], const uint8_t arg1[32])
{
	uint32_t x1 = ((uint32_t)(arg1[31]) << 18);
	uint32_t x2 = ((uint32_t)(arg1[30]) << 10);
	uint32_t x3 = ((uint32_t)(arg1[29]) << 2);
	uint32_t x4 = ((uint32_t)(arg1[28]) << 20);
	uint32_t x5 = ((uint32_t)(arg1[27]) << 12);
	uint32_t x6 = ((uint32_t)(arg1[26]) << 4);
	uint32_t x7 = ((uint32_t)(arg1[25]) << 21);
	uint32_t x8 = ((uint32_t)(arg1[24]) << 13);
	uint32_t x9 = ((uint32_t)(arg1[23]) << 5);
	uint32_t x10 = ((uint32_t)(arg1[22]) << 23);
	uint32_t x11 = ((uint32_t)(arg1[21]) << 15);
	uint32_t x12 = ((uint32_t)(arg1[20]) << 7);
	uint32_t x13 = ((uint32_t)(arg1[19]) << 24);
	uint32_t x14 = ((uint32_t)(arg1[18]) << 16);
	uint32_t x15 = ((uint32_t)(arg1[17]) << 8);
	uint8_t x16 = (arg1[16]);
	uint32_t x17 = ((uint32_t)(arg1[15]) << 18);
	uint32_t x18 = ((uint32_t)(arg1[14]) << 10);
	uint32_t x19 = ((uint32_t)(arg1[13]) << 2);
	uint32_t x20 = ((uint32_t)(arg1[12]) << 19);
	uint32_t x21 = ((uint32_t)(arg1[11]) << 11);
	uint32_t x22 = ((uint32_t)(arg1[10]) << 3);
	uint32_t x23 = ((uint32_t)(arg1[9]) << 21);
	uint32_t x24 = ((uint32_t)(arg1[8]) << 13);
	uint32_t x25 = ((uint32_t)(arg1[7]) << 5);
	uint32_t x26 = ((uint32_t)(arg1[6]) << 22);
	uint32_t x27 = ((uint32_t)(arg1[5]) << 14);
	uint32_t x28 = ((uint32_t)(arg1[4]) << 6);
	uint32_t x29 = ((uint32_t)(arg1[3]) << 24);
	uint32_t x30 = ((uint32_t)(arg1[2]) << 16);
	uint32_t x31 = ((uint32_t)(arg1[1]) << 8);
	uint8_t x32 = (arg1[0]);
	uint32_t x33 = (x32 + (x31 + (x30 + x29)));
	uint8_t x34 = (uint8_t)(x33 >> 26);
	uint32_t x35 = (x33 & UINT32_C(0x3ffffff));
	uint32_t x36 = (x3 + (x2 + x1));
	uint32_t x37 = (x6 + (x5 + x4));
	uint32_t x38 = (x9 + (x8 + x7));
	uint32_t x39 = (x12 + (x11 + x10));
	uint32_t x40 = (x16 + (x15 + (x14 + x13)));
	uint32_t x41 = (x19 + (x18 + x17));
	uint32_t x42 = (x22 + (x21 + x20));
	uint32_t x43 = (x25 + (x24 + x23));
	uint32_t x44 = (x28 + (x27 + x26));
	uint32_t x45 = (x34 + x44);
	uint8_t x46 = (uint8_t)(x45 >> 25);
	uint32_t x47 = (x45 & UINT32_C(0x1ffffff));
	uint32_t x48 = (x46 + x43);
	uint8_t x49 = (uint8_t)(x48 >> 26);
	uint32_t x50 = (x48 & UINT32_C(0x3ffffff));
	uint32_t x51 = (x49 + x42);
	uint8_t x52 = (uint8_t)(x51 >> 25);
	uint32_t x53 = (x51 & UINT32_C(0x1ffffff));
	uint32_t x54 = (x52 + x41);
	uint32_t x55 = (x54 & UINT32_C(0x3ffffff));
	uint8_t x56 = (uint8_t)(x40 >> 25);
	uint32_t x57 = (x40 & UINT32_C(0x1ffffff));
	uint32_t x58 = (x56 + x39);
	uint8_t x59 = (uint8_t)(x58 >> 26);
	uint32_t x60 = (x58 & UINT32_C(0x3ffffff));
	uint32_t x61 = (x59 + x38);
	uint8_t x62 = (uint8_t)(x61 >> 25);
	uint32_t x63 = (x61 & UINT32_C(0x1ffffff));
	uint32_t x64 = (x62 + x37);
	uint8_t x65 = (uint8_t)(x64 >> 26);
	uint32_t x66 = (x64 & UINT32_C(0x3ffffff));
	uint32_t x67 = (x65 + x36);
	out1[0] = x35;
	out1[1] = x47;
	out1[2] = x50;
	out1[3] = x53;
	out1[4] = x55;
	out1[5] = x57;
	out1[6] = x60;
	out1[7] = x63;
	out1[8] = x66;
	out1[9] = x67;
}

// Definitions

// fe means field element. Here the field is \Z/(2^255-19). An element t,
// entries t[0]...t[9], represents the integer t[0]+2^26 t[1]+2^51 t[2]+2^77
// t[3]+2^102 t[4]+...+2^230 t[9].
// fe limbs are bounded by 1.125*2^26,1.125*2^25,1.125*2^26,1.125*2^25,etc.
// Multiplication and carrying produce fe from fe_loose.
typedef struct fe {
	uint32_t v[10];
} fe;

// fe_loose limbs are bounded by 3.375*2^26,3.375*2^25,3.375*2^26,3.375*2^25,etc.
// Addition and subtraction produce fe_loose from (fe, fe).
typedef struct fe_loose {
	uint32_t v[10];
} fe_loose;

// ge means group element.
//
// Here the group is the set of pairs (x,y) of field elements (see fe.h)
// satisfying -x^2 + y^2 = 1 + d x^2y^2
// where d = -121665/121666.
//
// Representations:
//   ge_p2 (projective): (X:Y:Z) satisfying x=X/Z, y=Y/Z
//   ge_p3 (extended): (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
//   ge_p1p1 (completed): ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
//   ge_precomp (Duif): (y+x,y-x,2dxy)

typedef struct {
	fe X;
	fe Y;
	fe Z;
} ge_p2;

typedef struct {
	fe X;
	fe Y;
	fe Z;
	fe T;
} ge_p3;

typedef struct {
	fe_loose X;
	fe_loose Y;
	fe_loose Z;
	fe_loose T;
} ge_p1p1;

typedef struct {
	fe_loose yplusx;
	fe_loose yminusx;
	fe_loose xy2d;
} ge_precomp;

typedef struct {
	fe_loose YplusX;
	fe_loose YminusX;
	fe_loose Z;
	fe_loose T2d;
} ge_cached;

// Constants.

static const fe d = { { 56195235, 13857412, 51736253, 6949390, 114729, 24766616,
			60832955, 30306712, 48412415, 21499315 } };

static const fe sqrtm1 = { { 34513072, 25610706, 9377949, 3500415, 12389472,
			     33281959, 41962654, 31548777, 326685, 11406482 } };

static const fe d2 = { { 45281625, 27714825, 36363642, 13898781, 229458,
			 15978800, 54557047, 27058993, 29715967, 9444199 } };

// Bi[i] = (2*i+1)*B
static const ge_precomp Bi[8] = {
	{
		{ { 25967493, 19198397, 29566455, 3660896, 54414519, 4014786,
		    27544626, 21800161, 61029707, 2047604

		} },
		{ { 54563134, 934261, 64385954, 3049989, 66381436, 9406985,
		    12720692, 5043384, 19500929, 18085054

		} },
		{ { 58370664, 4489569, 9688441, 18769238, 10184608, 21191052,
		    29287918, 11864899, 42594502, 29115885 } },
	},
	{
		{ { 15636272, 23865875, 24204772, 25642034, 616976, 16869170,
		    27787599, 18782243, 28944399, 32004408 } },
		{ { 16568933, 4717097, 55552716, 32452109, 15682895, 21747389,
		    16354576, 21778470, 7689661, 11199574 } },
		{ { 30464137, 27578307, 55329429, 17883566, 23220364, 15915852,
		    7512774, 10017326, 49359771, 23634074 } },
	},
	{
		{ { 10861363, 11473154, 27284546, 1981175, 37044515, 12577860,
		    32867885, 14515107, 51670560, 10819379 } },
		{ { 4708026, 6336745, 20377586, 9066809, 55836755, 6594695,
		    41455196, 12483687, 54440373, 5581305 } },
		{ { 19563141, 16186464, 37722007, 4097518, 10237984, 29206317,
		    28542349, 13850243, 43430843, 17738489 } },
	},
	{
		{ { 5153727, 9909285, 1723747, 30776558, 30523604, 5516873,
		    19480852, 5230134, 43156425, 18378665 } },
		{ { 36839857, 30090922, 7665485, 10083793, 28475525, 1649722,
		    20654025, 16520125, 30598449, 7715701 } },
		{ { 28881826, 14381568, 9657904, 3680757, 46927229, 7843315,
		    35708204, 1370707, 29794553, 32145132 } },
	},
	{
		{ { 44589871, 26862249, 14201701, 24808930, 43598457, 8844725,
		    18474211, 32192982, 54046167, 13821876 } },
		{ { 60653668, 25714560, 3374701, 28813570, 40010246, 22982724,
		    31655027, 26342105, 18853321, 19333481 } },
		{ { 4566811, 20590564, 38133974, 21313742, 59506191, 30723862,
		    58594505, 23123294, 2207752, 30344648 } },
	},
	{
		{ { 41954014, 29368610, 29681143, 7868801, 60254203, 24130566,
		    54671499, 32891431, 35997400, 17421995 } },
		{ { 25576264, 30851218, 7349803, 21739588, 16472781, 9300885,
		    3844789, 15725684, 171356, 6466918 } },
		{ { 23103977, 13316479, 9739013, 17404951, 817874, 18515490,
		    8965338, 19466374, 36393951, 16193876 } },
	},
	{
		{ { 33587053, 3180712, 64714734, 14003686, 50205390, 17283591,
		    17238397, 4729455, 49034351, 9256799 } },
		{ { 41926547, 29380300, 32336397, 5036987, 45872047, 11360616,
		    22616405, 9761698, 47281666, 630304 } },
		{ { 53388152, 2639452, 42871404, 26147950, 9494426, 27780403,
		    60554312, 17593437, 64659607, 19263131 } },
	},
	{
		{ { 63957664, 28508356, 9282713, 6866145, 35201802, 32691408,
		    48168288, 15033783, 25105118, 25659556 } },
		{ { 42782475, 15950225, 35307649, 18961608, 55446126, 28463506,
		    1573891, 30928545, 2198789, 17749813 } },
		{ { 64009494, 10324966, 64867251, 7453182, 61661885, 30818928,
		    53296841, 17317989, 34647629, 21263748 } },
	},
};

static void fe_frombytes_strict(fe *h, const uint8_t s[32])
{
	// |fiat_25519_from_bytes| requires the top-most bit be clear.
	fiat_25519_from_bytes(h->v, s);
}

static void fe_frombytes(fe *h, const uint8_t s[32])
{
	uint8_t s_copy[32];
	memcpy(s_copy, s, 32);
	s_copy[31] &= 0x7f;
	fe_frombytes_strict(h, s_copy);
}

static void fe_tobytes(uint8_t s[32], const fe *f)
{
	fiat_25519_to_bytes(s, f->v);
}

// h = 0
static void fe_0(fe *h)
{
	memset(h, 0, sizeof(fe));
}

// h = 1
static void fe_1(fe *h)
{
	memset(h, 0, sizeof(fe));
	h->v[0] = 1;
}

// h = f + g
// Can overlap h with f or g.
static void fe_add(fe_loose *h, const fe *f, const fe *g)
{
	fiat_25519_add(h->v, f->v, g->v);
}

// h = f - g
// Can overlap h with f or g.
static void fe_sub(fe_loose *h, const fe *f, const fe *g)
{
	fiat_25519_sub(h->v, f->v, g->v);
}

static void fe_carry(fe *h, const fe_loose *f)
{
	fiat_25519_carry(h->v, f->v);
}

static void fe_mul_impl(uint32_t out[10], const uint32_t in1[10],
			const uint32_t in2[10])
{
	fiat_25519_carry_mul(out, in1, in2);
}

static void fe_mul_ltt(fe_loose *h, const fe *f, const fe *g)
{
	fe_mul_impl(h->v, f->v, g->v);
}

static void fe_mul_ttt(fe *h, const fe *f, const fe *g)
{
	fe_mul_impl(h->v, f->v, g->v);
}

static void fe_mul_tlt(fe *h, const fe_loose *f, const fe *g)
{
	fe_mul_impl(h->v, f->v, g->v);
}

static void fe_mul_ttl(fe *h, const fe *f, const fe_loose *g)
{
	fe_mul_impl(h->v, f->v, g->v);
}

static void fe_mul_tll(fe *h, const fe_loose *f, const fe_loose *g)
{
	fe_mul_impl(h->v, f->v, g->v);
}

static void fe_sq_tl(fe *h, const fe_loose *f)
{
	fiat_25519_carry_square(h->v, f->v);
}

static void fe_sq_tt(fe *h, const fe *f)
{
	fiat_25519_carry_square(h->v, f->v);
}

// h = -f
static void fe_neg(fe_loose *h, const fe *f)
{
	fiat_25519_opp(h->v, f->v);
}

// h = f
static void fe_copy(fe *h, const fe *f)
{
	memmove(h, f, sizeof(fe));
}

static void fe_copy_lt(fe_loose *h, const fe *f)
{
	memmove(h, f, sizeof(fe));
}

static void fe_loose_invert(fe *out, const fe_loose *z)
{
	fe t0;
	fe t1;
	fe t2;
	fe t3;
	int i;

	fe_sq_tl(&t0, z);
	fe_sq_tt(&t1, &t0);
	for (i = 1; i < 2; ++i) {
		fe_sq_tt(&t1, &t1);
	}
	fe_mul_tlt(&t1, z, &t1);
	fe_mul_ttt(&t0, &t0, &t1);
	fe_sq_tt(&t2, &t0);
	fe_mul_ttt(&t1, &t1, &t2);
	fe_sq_tt(&t2, &t1);
	for (i = 1; i < 5; ++i) {
		fe_sq_tt(&t2, &t2);
	}
	fe_mul_ttt(&t1, &t2, &t1);
	fe_sq_tt(&t2, &t1);
	for (i = 1; i < 10; ++i) {
		fe_sq_tt(&t2, &t2);
	}
	fe_mul_ttt(&t2, &t2, &t1);
	fe_sq_tt(&t3, &t2);
	for (i = 1; i < 20; ++i) {
		fe_sq_tt(&t3, &t3);
	}
	fe_mul_ttt(&t2, &t3, &t2);
	fe_sq_tt(&t2, &t2);
	for (i = 1; i < 10; ++i) {
		fe_sq_tt(&t2, &t2);
	}
	fe_mul_ttt(&t1, &t2, &t1);
	fe_sq_tt(&t2, &t1);
	for (i = 1; i < 50; ++i) {
		fe_sq_tt(&t2, &t2);
	}
	fe_mul_ttt(&t2, &t2, &t1);
	fe_sq_tt(&t3, &t2);
	for (i = 1; i < 100; ++i) {
		fe_sq_tt(&t3, &t3);
	}
	fe_mul_ttt(&t2, &t3, &t2);
	fe_sq_tt(&t2, &t2);
	for (i = 1; i < 50; ++i) {
		fe_sq_tt(&t2, &t2);
	}
	fe_mul_ttt(&t1, &t2, &t1);
	fe_sq_tt(&t1, &t1);
	for (i = 1; i < 5; ++i) {
		fe_sq_tt(&t1, &t1);
	}
	fe_mul_ttt(out, &t1, &t0);
}

static void fe_invert(fe *out, const fe *z)
{
	fe_loose l;
	fe_copy_lt(&l, z);
	fe_loose_invert(out, &l);
}

// return 0 if f == 0
// return 1 if f != 0
static int fe_isnonzero(const fe_loose *f)
{
	fe tight;
	fe_carry(&tight, f);
	uint8_t s[32];
	fe_tobytes(s, &tight);

	static const uint8_t zero[32] = { 0 };
	return memcmp_ct(s, zero, sizeof(zero)) != 0;
}

// return 1 if f is in {1,3,5,...,q-2}
// return 0 if f is in {0,2,4,...,q-1}
static int fe_isnegative(const fe *f)
{
	uint8_t s[32];
	fe_tobytes(s, f);
	return s[0] & 1;
}

static void fe_sq2_tt(fe *h, const fe *f)
{
	// h = f^2
	fe_sq_tt(h, f);

	// h = h + h
	fe_loose tmp;
	fe_add(&tmp, h, h);
	fe_carry(h, &tmp);
}

static void fe_pow22523(fe *out, const fe *z)
{
	fe t0;
	fe t1;
	fe t2;
	int i;

	fe_sq_tt(&t0, z);
	fe_sq_tt(&t1, &t0);
	for (i = 1; i < 2; ++i) {
		fe_sq_tt(&t1, &t1);
	}
	fe_mul_ttt(&t1, z, &t1);
	fe_mul_ttt(&t0, &t0, &t1);
	fe_sq_tt(&t0, &t0);
	fe_mul_ttt(&t0, &t1, &t0);
	fe_sq_tt(&t1, &t0);
	for (i = 1; i < 5; ++i) {
		fe_sq_tt(&t1, &t1);
	}
	fe_mul_ttt(&t0, &t1, &t0);
	fe_sq_tt(&t1, &t0);
	for (i = 1; i < 10; ++i) {
		fe_sq_tt(&t1, &t1);
	}
	fe_mul_ttt(&t1, &t1, &t0);
	fe_sq_tt(&t2, &t1);
	for (i = 1; i < 20; ++i) {
		fe_sq_tt(&t2, &t2);
	}
	fe_mul_ttt(&t1, &t2, &t1);
	fe_sq_tt(&t1, &t1);
	for (i = 1; i < 10; ++i) {
		fe_sq_tt(&t1, &t1);
	}
	fe_mul_ttt(&t0, &t1, &t0);
	fe_sq_tt(&t1, &t0);
	for (i = 1; i < 50; ++i) {
		fe_sq_tt(&t1, &t1);
	}
	fe_mul_ttt(&t1, &t1, &t0);
	fe_sq_tt(&t2, &t1);
	for (i = 1; i < 100; ++i) {
		fe_sq_tt(&t2, &t2);
	}
	fe_mul_ttt(&t1, &t2, &t1);
	fe_sq_tt(&t1, &t1);
	for (i = 1; i < 50; ++i) {
		fe_sq_tt(&t1, &t1);
	}
	fe_mul_ttt(&t0, &t1, &t0);
	fe_sq_tt(&t0, &t0);
	for (i = 1; i < 2; ++i) {
		fe_sq_tt(&t0, &t0);
	}
	fe_mul_ttt(out, &t0, z);
}

static void x25519_ge_tobytes(uint8_t s[32], const ge_p2 *h)
{
	fe recip;
	fe x;
	fe y;

	fe_invert(&recip, &h->Z);
	fe_mul_ttt(&x, &h->X, &recip);
	fe_mul_ttt(&y, &h->Y, &recip);
	fe_tobytes(s, &y);
	s[31] ^= fe_isnegative(&x) << 7;
}

static int x25519_ge_frombytes_vartime(ge_p3 *h, const uint8_t s[32])
{
	fe u;
	fe_loose v;
	fe v3;
	fe vxx;
	fe_loose check;

	fe_frombytes(&h->Y, s);
	fe_1(&h->Z);
	fe_sq_tt(&v3, &h->Y);
	fe_mul_ttt(&vxx, &v3, &d);
	fe_sub(&v, &v3, &h->Z); // u = y^2-1
	fe_carry(&u, &v);
	fe_add(&v, &vxx, &h->Z); // v = dy^2+1

	fe_sq_tl(&v3, &v);
	fe_mul_ttl(&v3, &v3, &v); // v3 = v^3
	fe_sq_tt(&h->X, &v3);
	fe_mul_ttl(&h->X, &h->X, &v);
	fe_mul_ttt(&h->X, &h->X, &u); // x = uv^7

	fe_pow22523(&h->X, &h->X); // x = (uv^7)^((q-5)/8)
	fe_mul_ttt(&h->X, &h->X, &v3);
	fe_mul_ttt(&h->X, &h->X, &u); // x = uv^3(uv^7)^((q-5)/8)

	fe_sq_tt(&vxx, &h->X);
	fe_mul_ttl(&vxx, &vxx, &v);
	fe_sub(&check, &vxx, &u);
	if (fe_isnonzero(&check)) {
		fe_add(&check, &vxx, &u);
		if (fe_isnonzero(&check)) {
			return 0;
		}
		fe_mul_ttt(&h->X, &h->X, &sqrtm1);
	}

	if (fe_isnegative(&h->X) != (s[31] >> 7)) {
		fe_loose t;
		fe_neg(&t, &h->X);
		fe_carry(&h->X, &t);
	}

	fe_mul_ttt(&h->T, &h->X, &h->Y);
	return 1;
}

static void ge_p2_0(ge_p2 *h)
{
	fe_0(&h->X);
	fe_1(&h->Y);
	fe_1(&h->Z);
}

// r = p
static void ge_p3_to_p2(ge_p2 *r, const ge_p3 *p)
{
	fe_copy(&r->X, &p->X);
	fe_copy(&r->Y, &p->Y);
	fe_copy(&r->Z, &p->Z);
}

// r = p
static void x25519_ge_p3_to_cached(ge_cached *r, const ge_p3 *p)
{
	fe_add(&r->YplusX, &p->Y, &p->X);
	fe_sub(&r->YminusX, &p->Y, &p->X);
	fe_copy_lt(&r->Z, &p->Z);
	fe_mul_ltt(&r->T2d, &p->T, &d2);
}

// r = p
static void x25519_ge_p1p1_to_p2(ge_p2 *r, const ge_p1p1 *p)
{
	fe_mul_tll(&r->X, &p->X, &p->T);
	fe_mul_tll(&r->Y, &p->Y, &p->Z);
	fe_mul_tll(&r->Z, &p->Z, &p->T);
}

// r = p
static void x25519_ge_p1p1_to_p3(ge_p3 *r, const ge_p1p1 *p)
{
	fe_mul_tll(&r->X, &p->X, &p->T);
	fe_mul_tll(&r->Y, &p->Y, &p->Z);
	fe_mul_tll(&r->Z, &p->Z, &p->T);
	fe_mul_tll(&r->T, &p->X, &p->Y);
}

// r = 2 * p
static void ge_p2_dbl(ge_p1p1 *r, const ge_p2 *p)
{
	fe trX, trZ, trT;
	fe t0;

	fe_sq_tt(&trX, &p->X);
	fe_sq_tt(&trZ, &p->Y);
	fe_sq2_tt(&trT, &p->Z);
	fe_add(&r->Y, &p->X, &p->Y);
	fe_sq_tl(&t0, &r->Y);

	fe_add(&r->Y, &trZ, &trX);
	fe_sub(&r->Z, &trZ, &trX);
	fe_carry(&trZ, &r->Y);
	fe_sub(&r->X, &t0, &trZ);
	fe_carry(&trZ, &r->Z);
	fe_sub(&r->T, &trT, &trZ);
}

// r = 2 * p
static void ge_p3_dbl(ge_p1p1 *r, const ge_p3 *p)
{
	ge_p2 q;
	ge_p3_to_p2(&q, p);
	ge_p2_dbl(r, &q);
}

// r = p + q
static void ge_madd(ge_p1p1 *r, const ge_p3 *p, const ge_precomp *q)
{
	fe trY, trZ, trT;

	fe_add(&r->X, &p->Y, &p->X);
	fe_sub(&r->Y, &p->Y, &p->X);
	fe_mul_tll(&trZ, &r->X, &q->yplusx);
	fe_mul_tll(&trY, &r->Y, &q->yminusx);
	fe_mul_tlt(&trT, &q->xy2d, &p->T);
	fe_add(&r->T, &p->Z, &p->Z);
	fe_sub(&r->X, &trZ, &trY);
	fe_add(&r->Y, &trZ, &trY);
	fe_carry(&trZ, &r->T);
	fe_add(&r->Z, &trZ, &trT);
	fe_sub(&r->T, &trZ, &trT);
}

// r = p - q
static void ge_msub(ge_p1p1 *r, const ge_p3 *p, const ge_precomp *q)
{
	fe trY, trZ, trT;

	fe_add(&r->X, &p->Y, &p->X);
	fe_sub(&r->Y, &p->Y, &p->X);
	fe_mul_tll(&trZ, &r->X, &q->yminusx);
	fe_mul_tll(&trY, &r->Y, &q->yplusx);
	fe_mul_tlt(&trT, &q->xy2d, &p->T);
	fe_add(&r->T, &p->Z, &p->Z);
	fe_sub(&r->X, &trZ, &trY);
	fe_add(&r->Y, &trZ, &trY);
	fe_carry(&trZ, &r->T);
	fe_sub(&r->Z, &trZ, &trT);
	fe_add(&r->T, &trZ, &trT);
}

// r = p + q
static void x25519_ge_add(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q)
{
	fe trX, trY, trZ, trT;

	fe_add(&r->X, &p->Y, &p->X);
	fe_sub(&r->Y, &p->Y, &p->X);
	fe_mul_tll(&trZ, &r->X, &q->YplusX);
	fe_mul_tll(&trY, &r->Y, &q->YminusX);
	fe_mul_tlt(&trT, &q->T2d, &p->T);
	fe_mul_ttl(&trX, &p->Z, &q->Z);
	fe_add(&r->T, &trX, &trX);
	fe_sub(&r->X, &trZ, &trY);
	fe_add(&r->Y, &trZ, &trY);
	fe_carry(&trZ, &r->T);
	fe_add(&r->Z, &trZ, &trT);
	fe_sub(&r->T, &trZ, &trT);
}

// r = p - q
static void x25519_ge_sub(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q)
{
	fe trX, trY, trZ, trT;

	fe_add(&r->X, &p->Y, &p->X);
	fe_sub(&r->Y, &p->Y, &p->X);
	fe_mul_tll(&trZ, &r->X, &q->YminusX);
	fe_mul_tll(&trY, &r->Y, &q->YplusX);
	fe_mul_tlt(&trT, &q->T2d, &p->T);
	fe_mul_ttl(&trX, &p->Z, &q->Z);
	fe_add(&r->T, &trX, &trX);
	fe_sub(&r->X, &trZ, &trY);
	fe_add(&r->Y, &trZ, &trY);
	fe_carry(&trZ, &r->T);
	fe_sub(&r->Z, &trZ, &trT);
	fe_add(&r->T, &trZ, &trT);
}

static void slide(signed char *r, const uint8_t *a)
{
	int i;
	int b;
	int k;

	for (i = 0; i < 256; ++i) {
		r[i] = 1 & (a[i >> 3] >> (i & 7));
	}

	for (i = 0; i < 256; ++i) {
		if (r[i]) {
			for (b = 1; b <= 6 && i + b < 256; ++b) {
				if (r[i + b]) {
					if (r[i] + (r[i + b] << b) <= 15) {
						r[i] += r[i + b] << b;
						r[i + b] = 0;
					} else if (r[i] - (r[i + b] << b) >=
						   -15) {
						r[i] -= r[i + b] << b;
						for (k = i + b; k < 256; ++k) {
							if (!r[k]) {
								r[k] = 1;
								break;
							}
							r[k] = 0;
						}
					} else {
						break;
					}
				}
			}
		}
	}
}

// r = a * A + b * B
// where a = a[0]+256*a[1]+...+256^31 a[31].
// and b = b[0]+256*b[1]+...+256^31 b[31].
// B is the Ed25519 base point (x,4/5) with x positive.
static void ge_double_scalarmult_vartime(ge_p2 *r, const uint8_t *a,
					 const ge_p3 *A, const uint8_t *b)
{
	signed char aslide[256];
	signed char bslide[256];
	ge_cached Ai[8]; // A,3A,5A,7A,9A,11A,13A,15A
	ge_p1p1 t;
	ge_p3 u;
	ge_p3 A2;
	int i;

	slide(aslide, a);
	slide(bslide, b);

	x25519_ge_p3_to_cached(&Ai[0], A);
	ge_p3_dbl(&t, A);
	x25519_ge_p1p1_to_p3(&A2, &t);
	x25519_ge_add(&t, &A2, &Ai[0]);
	x25519_ge_p1p1_to_p3(&u, &t);
	x25519_ge_p3_to_cached(&Ai[1], &u);
	x25519_ge_add(&t, &A2, &Ai[1]);
	x25519_ge_p1p1_to_p3(&u, &t);
	x25519_ge_p3_to_cached(&Ai[2], &u);
	x25519_ge_add(&t, &A2, &Ai[2]);
	x25519_ge_p1p1_to_p3(&u, &t);
	x25519_ge_p3_to_cached(&Ai[3], &u);
	x25519_ge_add(&t, &A2, &Ai[3]);
	x25519_ge_p1p1_to_p3(&u, &t);
	x25519_ge_p3_to_cached(&Ai[4], &u);
	x25519_ge_add(&t, &A2, &Ai[4]);
	x25519_ge_p1p1_to_p3(&u, &t);
	x25519_ge_p3_to_cached(&Ai[5], &u);
	x25519_ge_add(&t, &A2, &Ai[5]);
	x25519_ge_p1p1_to_p3(&u, &t);
	x25519_ge_p3_to_cached(&Ai[6], &u);
	x25519_ge_add(&t, &A2, &Ai[6]);
	x25519_ge_p1p1_to_p3(&u, &t);
	x25519_ge_p3_to_cached(&Ai[7], &u);

	ge_p2_0(r);

	for (i = 255; i >= 0; --i) {
		if (aslide[i] || bslide[i]) {
			break;
		}
	}

	for (; i >= 0; --i) {
		ge_p2_dbl(&t, r);

		if (aslide[i] > 0) {
			x25519_ge_p1p1_to_p3(&u, &t);
			x25519_ge_add(&t, &u, &Ai[aslide[i] / 2]);
		} else if (aslide[i] < 0) {
			x25519_ge_p1p1_to_p3(&u, &t);
			x25519_ge_sub(&t, &u, &Ai[(-aslide[i]) / 2]);
		}

		if (bslide[i] > 0) {
			x25519_ge_p1p1_to_p3(&u, &t);
			ge_madd(&t, &u, &Bi[bslide[i] / 2]);
		} else if (bslide[i] < 0) {
			x25519_ge_p1p1_to_p3(&u, &t);
			ge_msub(&t, &u, &Bi[(-bslide[i]) / 2]);
		}

		x25519_ge_p1p1_to_p2(r, &t);
	}
}

// int64_lshift21 returns |a << 21| but is defined when shifting bits into the
// sign bit. This works around a language flaw in C.
static inline int64_t int64_lshift21(int64_t a)
{
	return (int64_t)((uint64_t)a << 21);
}

// The set of scalars is \Z/l
// where l = 2^252 + 27742317777372353535851937790883648493.

// Input:
//   s[0]+256*s[1]+...+256^63*s[63] = s
//
// Output:
//   s[0]+256*s[1]+...+256^31*s[31] = s mod l
//   where l = 2^252 + 27742317777372353535851937790883648493.
//   Overwrites s in place.
static void x25519_sc_reduce(uint8_t s[64])
{
	int64_t s0 = 2097151 & load_le24(s);
	int64_t s1 = 2097151 & (load_le32(s + 2) >> 5);
	int64_t s2 = 2097151 & (load_le24(s + 5) >> 2);
	int64_t s3 = 2097151 & (load_le32(s + 7) >> 7);
	int64_t s4 = 2097151 & (load_le32(s + 10) >> 4);
	int64_t s5 = 2097151 & (load_le24(s + 13) >> 1);
	int64_t s6 = 2097151 & (load_le32(s + 15) >> 6);
	int64_t s7 = 2097151 & (load_le24(s + 18) >> 3);
	int64_t s8 = 2097151 & load_le24(s + 21);
	int64_t s9 = 2097151 & (load_le32(s + 23) >> 5);
	int64_t s10 = 2097151 & (load_le24(s + 26) >> 2);
	int64_t s11 = 2097151 & (load_le32(s + 28) >> 7);
	int64_t s12 = 2097151 & (load_le32(s + 31) >> 4);
	int64_t s13 = 2097151 & (load_le24(s + 34) >> 1);
	int64_t s14 = 2097151 & (load_le32(s + 36) >> 6);
	int64_t s15 = 2097151 & (load_le24(s + 39) >> 3);
	int64_t s16 = 2097151 & load_le24(s + 42);
	int64_t s17 = 2097151 & (load_le32(s + 44) >> 5);
	int64_t s18 = 2097151 & (load_le24(s + 47) >> 2);
	int64_t s19 = 2097151 & (load_le32(s + 49) >> 7);
	int64_t s20 = 2097151 & (load_le32(s + 52) >> 4);
	int64_t s21 = 2097151 & (load_le24(s + 55) >> 1);
	int64_t s22 = 2097151 & (load_le32(s + 57) >> 6);
	int64_t s23 = (load_le32(s + 60) >> 3);
	int64_t carry0;
	int64_t carry1;
	int64_t carry2;
	int64_t carry3;
	int64_t carry4;
	int64_t carry5;
	int64_t carry6;
	int64_t carry7;
	int64_t carry8;
	int64_t carry9;
	int64_t carry10;
	int64_t carry11;
	int64_t carry12;
	int64_t carry13;
	int64_t carry14;
	int64_t carry15;
	int64_t carry16;

	s11 += s23 * 666643;
	s12 += s23 * 470296;
	s13 += s23 * 654183;
	s14 -= s23 * 997805;
	s15 += s23 * 136657;
	s16 -= s23 * 683901;
	s23 = 0;

	s10 += s22 * 666643;
	s11 += s22 * 470296;
	s12 += s22 * 654183;
	s13 -= s22 * 997805;
	s14 += s22 * 136657;
	s15 -= s22 * 683901;
	s22 = 0;

	s9 += s21 * 666643;
	s10 += s21 * 470296;
	s11 += s21 * 654183;
	s12 -= s21 * 997805;
	s13 += s21 * 136657;
	s14 -= s21 * 683901;
	s21 = 0;

	s8 += s20 * 666643;
	s9 += s20 * 470296;
	s10 += s20 * 654183;
	s11 -= s20 * 997805;
	s12 += s20 * 136657;
	s13 -= s20 * 683901;
	s20 = 0;

	s7 += s19 * 666643;
	s8 += s19 * 470296;
	s9 += s19 * 654183;
	s10 -= s19 * 997805;
	s11 += s19 * 136657;
	s12 -= s19 * 683901;
	s19 = 0;

	s6 += s18 * 666643;
	s7 += s18 * 470296;
	s8 += s18 * 654183;
	s9 -= s18 * 997805;
	s10 += s18 * 136657;
	s11 -= s18 * 683901;
	s18 = 0;

	carry6 = (s6 + (1 << 20)) >> 21;
	s7 += carry6;
	s6 -= int64_lshift21(carry6);
	carry8 = (s8 + (1 << 20)) >> 21;
	s9 += carry8;
	s8 -= int64_lshift21(carry8);
	carry10 = (s10 + (1 << 20)) >> 21;
	s11 += carry10;
	s10 -= int64_lshift21(carry10);
	carry12 = (s12 + (1 << 20)) >> 21;
	s13 += carry12;
	s12 -= int64_lshift21(carry12);
	carry14 = (s14 + (1 << 20)) >> 21;
	s15 += carry14;
	s14 -= int64_lshift21(carry14);
	carry16 = (s16 + (1 << 20)) >> 21;
	s17 += carry16;
	s16 -= int64_lshift21(carry16);

	carry7 = (s7 + (1 << 20)) >> 21;
	s8 += carry7;
	s7 -= int64_lshift21(carry7);
	carry9 = (s9 + (1 << 20)) >> 21;
	s10 += carry9;
	s9 -= int64_lshift21(carry9);
	carry11 = (s11 + (1 << 20)) >> 21;
	s12 += carry11;
	s11 -= int64_lshift21(carry11);
	carry13 = (s13 + (1 << 20)) >> 21;
	s14 += carry13;
	s13 -= int64_lshift21(carry13);
	carry15 = (s15 + (1 << 20)) >> 21;
	s16 += carry15;
	s15 -= int64_lshift21(carry15);

	s5 += s17 * 666643;
	s6 += s17 * 470296;
	s7 += s17 * 654183;
	s8 -= s17 * 997805;
	s9 += s17 * 136657;
	s10 -= s17 * 683901;
	s17 = 0;

	s4 += s16 * 666643;
	s5 += s16 * 470296;
	s6 += s16 * 654183;
	s7 -= s16 * 997805;
	s8 += s16 * 136657;
	s9 -= s16 * 683901;
	s16 = 0;

	s3 += s15 * 666643;
	s4 += s15 * 470296;
	s5 += s15 * 654183;
	s6 -= s15 * 997805;
	s7 += s15 * 136657;
	s8 -= s15 * 683901;
	s15 = 0;

	s2 += s14 * 666643;
	s3 += s14 * 470296;
	s4 += s14 * 654183;
	s5 -= s14 * 997805;
	s6 += s14 * 136657;
	s7 -= s14 * 683901;
	s14 = 0;

	s1 += s13 * 666643;
	s2 += s13 * 470296;
	s3 += s13 * 654183;
	s4 -= s13 * 997805;
	s5 += s13 * 136657;
	s6 -= s13 * 683901;
	s13 = 0;

	s0 += s12 * 666643;
	s1 += s12 * 470296;
	s2 += s12 * 654183;
	s3 -= s12 * 997805;
	s4 += s12 * 136657;
	s5 -= s12 * 683901;
	s12 = 0;

	carry0 = (s0 + (1 << 20)) >> 21;
	s1 += carry0;
	s0 -= int64_lshift21(carry0);
	carry2 = (s2 + (1 << 20)) >> 21;
	s3 += carry2;
	s2 -= int64_lshift21(carry2);
	carry4 = (s4 + (1 << 20)) >> 21;
	s5 += carry4;
	s4 -= int64_lshift21(carry4);
	carry6 = (s6 + (1 << 20)) >> 21;
	s7 += carry6;
	s6 -= int64_lshift21(carry6);
	carry8 = (s8 + (1 << 20)) >> 21;
	s9 += carry8;
	s8 -= int64_lshift21(carry8);
	carry10 = (s10 + (1 << 20)) >> 21;
	s11 += carry10;
	s10 -= int64_lshift21(carry10);

	carry1 = (s1 + (1 << 20)) >> 21;
	s2 += carry1;
	s1 -= int64_lshift21(carry1);
	carry3 = (s3 + (1 << 20)) >> 21;
	s4 += carry3;
	s3 -= int64_lshift21(carry3);
	carry5 = (s5 + (1 << 20)) >> 21;
	s6 += carry5;
	s5 -= int64_lshift21(carry5);
	carry7 = (s7 + (1 << 20)) >> 21;
	s8 += carry7;
	s7 -= int64_lshift21(carry7);
	carry9 = (s9 + (1 << 20)) >> 21;
	s10 += carry9;
	s9 -= int64_lshift21(carry9);
	carry11 = (s11 + (1 << 20)) >> 21;
	s12 += carry11;
	s11 -= int64_lshift21(carry11);

	s0 += s12 * 666643;
	s1 += s12 * 470296;
	s2 += s12 * 654183;
	s3 -= s12 * 997805;
	s4 += s12 * 136657;
	s5 -= s12 * 683901;
	s12 = 0;

	carry0 = s0 >> 21;
	s1 += carry0;
	s0 -= int64_lshift21(carry0);
	carry1 = s1 >> 21;
	s2 += carry1;
	s1 -= int64_lshift21(carry1);
	carry2 = s2 >> 21;
	s3 += carry2;
	s2 -= int64_lshift21(carry2);
	carry3 = s3 >> 21;
	s4 += carry3;
	s3 -= int64_lshift21(carry3);
	carry4 = s4 >> 21;
	s5 += carry4;
	s4 -= int64_lshift21(carry4);
	carry5 = s5 >> 21;
	s6 += carry5;
	s5 -= int64_lshift21(carry5);
	carry6 = s6 >> 21;
	s7 += carry6;
	s6 -= int64_lshift21(carry6);
	carry7 = s7 >> 21;
	s8 += carry7;
	s7 -= int64_lshift21(carry7);
	carry8 = s8 >> 21;
	s9 += carry8;
	s8 -= int64_lshift21(carry8);
	carry9 = s9 >> 21;
	s10 += carry9;
	s9 -= int64_lshift21(carry9);
	carry10 = s10 >> 21;
	s11 += carry10;
	s10 -= int64_lshift21(carry10);
	carry11 = s11 >> 21;
	s12 += carry11;
	s11 -= int64_lshift21(carry11);

	s0 += s12 * 666643;
	s1 += s12 * 470296;
	s2 += s12 * 654183;
	s3 -= s12 * 997805;
	s4 += s12 * 136657;
	s5 -= s12 * 683901;
	s12 = 0;

	carry0 = s0 >> 21;
	s1 += carry0;
	s0 -= int64_lshift21(carry0);
	carry1 = s1 >> 21;
	s2 += carry1;
	s1 -= int64_lshift21(carry1);
	carry2 = s2 >> 21;
	s3 += carry2;
	s2 -= int64_lshift21(carry2);
	carry3 = s3 >> 21;
	s4 += carry3;
	s3 -= int64_lshift21(carry3);
	carry4 = s4 >> 21;
	s5 += carry4;
	s4 -= int64_lshift21(carry4);
	carry5 = s5 >> 21;
	s6 += carry5;
	s5 -= int64_lshift21(carry5);
	carry6 = s6 >> 21;
	s7 += carry6;
	s6 -= int64_lshift21(carry6);
	carry7 = s7 >> 21;
	s8 += carry7;
	s7 -= int64_lshift21(carry7);
	carry8 = s8 >> 21;
	s9 += carry8;
	s8 -= int64_lshift21(carry8);
	carry9 = s9 >> 21;
	s10 += carry9;
	s9 -= int64_lshift21(carry9);
	carry10 = s10 >> 21;
	s11 += carry10;
	s10 -= int64_lshift21(carry10);

	s[0] = s0 >> 0;
	s[1] = s0 >> 8;
	s[2] = (s0 >> 16) | (s1 << 5);
	s[3] = s1 >> 3;
	s[4] = s1 >> 11;
	s[5] = (s1 >> 19) | (s2 << 2);
	s[6] = s2 >> 6;
	s[7] = (s2 >> 14) | (s3 << 7);
	s[8] = s3 >> 1;
	s[9] = s3 >> 9;
	s[10] = (s3 >> 17) | (s4 << 4);
	s[11] = s4 >> 4;
	s[12] = s4 >> 12;
	s[13] = (s4 >> 20) | (s5 << 1);
	s[14] = s5 >> 7;
	s[15] = (s5 >> 15) | (s6 << 6);
	s[16] = s6 >> 2;
	s[17] = s6 >> 10;
	s[18] = (s6 >> 18) | (s7 << 3);
	s[19] = s7 >> 5;
	s[20] = s7 >> 13;
	s[21] = s8 >> 0;
	s[22] = s8 >> 8;
	s[23] = (s8 >> 16) | (s9 << 5);
	s[24] = s9 >> 3;
	s[25] = s9 >> 11;
	s[26] = (s9 >> 19) | (s10 << 2);
	s[27] = s10 >> 6;
	s[28] = (s10 >> 14) | (s11 << 7);
	s[29] = s11 >> 1;
	s[30] = s11 >> 9;
	s[31] = s11 >> 17;
}

bool ed25519_verify(const uint8_t signature[64], const uint8_t public_key[32],
		    const void *message, size_t message_size)
{
	ge_p3 A;
	if ((signature[63] & 224) != 0 ||
	    !x25519_ge_frombytes_vartime(&A, public_key))
		return false;

	fe_loose t;
	fe_neg(&t, &A.X);
	fe_carry(&A.X, &t);
	fe_neg(&t, &A.T);
	fe_carry(&A.T, &t);

	uint8_t pkcopy[32];
	memcpy(pkcopy, public_key, 32);
	uint8_t rcopy[32];
	memcpy(rcopy, signature, 32);
	union {
		uint64_t u64[4];
		uint8_t u8[32];
	} scopy;
	memcpy(&scopy.u8[0], signature + 32, 32);

	// https://tools.ietf.org/html/rfc8032#section-5.1.7 requires that s be in
	// the range [0, order) in order to prevent signature malleability.

	// kOrder is the order of Curve25519 in little-endian form.
	static const uint64_t kOrder[4] = {
		UINT64_C(0x5812631a5cf5d3ed),
		UINT64_C(0x14def9dea2f79cd6),
		0,
		UINT64_C(0x1000000000000000),
	};
	for (size_t i = 3;; --i) {
		uint64_t le = swap_le64(scopy.u64[i]);
		if (le > kOrder[i]) {
			return false;
		} else if (le < kOrder[i]) {
			break;
		} else if (i == 0) {
			return false;
		}
	}

	uint8_t h[64];
	BCRYPT_ALG_HANDLE alg, hash;
	if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA512_ALGORITHM, NULL, 0)) ||
	    !NT_SUCCESS(BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0)) ||
	    !NT_SUCCESS(BCryptHashData(hash, (PUCHAR)signature, 32, 0)) ||
	    !NT_SUCCESS(BCryptHashData(hash, (PUCHAR)public_key, 32, 0)) ||
	    !NT_SUCCESS(BCryptHashData(hash, (PUCHAR)message, message_size, 0)) ||
	    !NT_SUCCESS(BCryptFinishHash(hash, h, 64, 0)) ||
	    !NT_SUCCESS(BCryptDestroyHash(hash)) ||
	    !NT_SUCCESS(BCryptCloseAlgorithmProvider(alg, 0)))
		return false;

	x25519_sc_reduce(h);

	ge_p2 R;
	ge_double_scalarmult_vartime(&R, h, &A, scopy.u8);

	uint8_t rcheck[32];
	x25519_ge_tobytes(rcheck, &R);

	return memcmp_ct(rcheck, rcopy, sizeof(rcheck)) == 0;
}

static const uint64_t blake2b_iv[8] = {
	0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
	0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
	0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const uint8_t blake2b_sigma[12][16] = {
	{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
	{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
	{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
	{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
	{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
	{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
	{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
	{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
	{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
	{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
};

#define G(r, i, a, b, c, d)                                                    \
	do {                                                                   \
		a = a + b + m[blake2b_sigma[r][2 * i + 0]];                    \
		d = ror64(d ^ a, 32);                                          \
		c = c + d;                                                     \
		b = ror64(b ^ c, 24);                                          \
		a = a + b + m[blake2b_sigma[r][2 * i + 1]];                    \
		d = ror64(d ^ a, 16);                                          \
		c = c + d;                                                     \
		b = ror64(b ^ c, 63);                                          \
	} while (0)

#define ROUND(r)                                                               \
	do {                                                                   \
		G(r, 0, v[0], v[4], v[8], v[12]);                              \
		G(r, 1, v[1], v[5], v[9], v[13]);                              \
		G(r, 2, v[2], v[6], v[10], v[14]);                             \
		G(r, 3, v[3], v[7], v[11], v[15]);                             \
		G(r, 4, v[0], v[5], v[10], v[15]);                             \
		G(r, 5, v[1], v[6], v[11], v[12]);                             \
		G(r, 6, v[2], v[7], v[8], v[13]);                              \
		G(r, 7, v[3], v[4], v[9], v[14]);                              \
	} while (0)

static void blake2b256_compress(struct blake2b256_state *state,
				const uint8_t block[128])
{
	uint64_t m[16];
	uint64_t v[16];

	for (int i = 0; i < 16; ++i)
		m[i] = load_le64(block + i * sizeof(m[i]));

	for (int i = 0; i < 8; ++i)
		v[i] = state->h[i];

	memcpy(v + 8, blake2b_iv, sizeof(blake2b_iv));
	v[12] ^= state->t[0];
	v[13] ^= state->t[1];
	v[14] ^= state->f[0];
	v[15] ^= state->f[1];

	for (int i = 0; i < 12; ++i)
		ROUND(i);
	for (int i = 0; i < 8; ++i)
		state->h[i] = state->h[i] ^ v[i] ^ v[i + 8];
}

void blake2b256_init(struct blake2b256_state *state)
{
	memset(state, 0, sizeof(*state));
	memcpy(state->h, blake2b_iv, sizeof(state->h));
	state->h[0] ^= 0x01010000 | 32;
}

void blake2b256_update(struct blake2b256_state *state, const uint8_t *in,
		       unsigned int inlen)
{
	const size_t left = state->buflen;
	const size_t fill = 128 - left;

	if (!inlen)
		return;

	if (inlen > fill) {
		state->buflen = 0;
		memcpy(state->buf + left, in, fill);
		state->t[0] += 128;
		state->t[1] += (state->t[0] < 128);
		blake2b256_compress(state, state->buf);
		in += fill;
		inlen -= fill;
		while (inlen > 128) {
			state->t[0] += 128;
			state->t[1] += (state->t[0] < 128);
			blake2b256_compress(state, in);
			in += 128;
			inlen -= 128;
		}
	}
	memcpy(state->buf + state->buflen, in, inlen);
	state->buflen += inlen;
}

void blake2b256_final(struct blake2b256_state *state, uint8_t out[32])
{
	state->t[0] += state->buflen;
	state->t[1] += (state->t[0] < state->buflen);
	state->f[0] = (uint64_t)-1;
	memset(state->buf + state->buflen, 0, 128 - state->buflen);
	blake2b256_compress(state, state->buf);

	for (int i = 0; i < 4; ++i)
		store_le64(out + i * sizeof(state->h[i]), state->h[i]);
}
