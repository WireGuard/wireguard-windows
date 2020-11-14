// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2017-2020, Loup Vaillant. All rights reserved.
 * Copyright (C) 2020 Jason A. Donenfeld. All Rights Reserved.
 */

#include "crypto.h"

#define FOR_T(type, i, start, end) for (type i = (start); i < (end); i++)
#define FOR(i, start, end)         FOR_T(size_t, i, start, end)
#define COPY(dst, src, size)       FOR(i, 0, size) (dst)[i] = (src)[i]
#define ZERO(buf, size)            FOR(i, 0, size) (buf)[i] = 0
#define MIN(a, b)                  ((a) <= (b) ? (a) : (b))
#define MAX(a, b)                  ((a) >= (b) ? (a) : (b))

typedef int8_t   i8;
typedef uint8_t  u8;
typedef int16_t  i16;
typedef uint32_t u32;
typedef int32_t  i32;
typedef int64_t  i64;
typedef uint64_t u64;

static const u8 zero[32] = {0};

// returns the smallest positive integer y such that
// (x + y) % pow_2  == 0
// Basically, it's how many bytes we need to add to "align" x.
// Only works when pow_2 is a power of 2.
// Note: we use ~x+1 instead of -x to avoid compiler warnings
static size_t align(size_t x, size_t pow_2)
{
	return (~x + 1) & (pow_2 - 1);
}

static u32 load24_le(const u8 s[3])
{
	return (u32)s[0]
		| ((u32)s[1] <<  8)
		| ((u32)s[2] << 16);
}

static u32 load32_le(const u8 s[4])
{
	return (u32)s[0]
		| ((u32)s[1] <<  8)
		| ((u32)s[2] << 16)
		| ((u32)s[3] << 24);
}

static u64 load64_le(const u8 s[8])
{
	return load32_le(s) | ((u64)load32_le(s+4) << 32);
}

static u64 load64_be(const u8 s[8])
{
	return((u64)s[0] << 56)
		| ((u64)s[1] << 48)
		| ((u64)s[2] << 40)
		| ((u64)s[3] << 32)
		| ((u64)s[4] << 24)
		| ((u64)s[5] << 16)
		| ((u64)s[6] <<  8)
		|  (u64)s[7];
}

static void store32_le(u8 out[4], u32 in)
{
	out[0] =  in        & 0xff;
	out[1] = (in >>  8) & 0xff;
	out[2] = (in >> 16) & 0xff;
	out[3] = (in >> 24) & 0xff;
}

static void store64_le(u8 out[8], u64 in)
{
	store32_le(out    , (u32)in );
	store32_le(out + 4, in >> 32);
}

static void store64_be(u8 out[8], u64 in)
{
	out[0] = (in >> 56) & 0xff;
	out[1] = (in >> 48) & 0xff;
	out[2] = (in >> 40) & 0xff;
	out[3] = (in >> 32) & 0xff;
	out[4] = (in >> 24) & 0xff;
	out[5] = (in >> 16) & 0xff;
	out[6] = (in >>  8) & 0xff;
	out[7] =  in        & 0xff;
}

static void load64_le_buf (u64 *dst, const u8 *src, size_t size) {
	FOR(i, 0, size) { dst[i] = load64_le(src + i*8); }
}
static void store64_le_buf(u8 *dst, const u64 *src, size_t size) {
	FOR(i, 0, size) { store64_le(dst + i*8, src[i]); }
}

static u64 rotr64(u64 x, u64 n) { return (x >> n) ^ (x << (64 - n)); }

static int neq0(u64 diff)
{
	// constant time comparison to zero
	// return diff != 0 ? -1 : 0
	u64 half = (diff >> 32) | ((u32)diff);
	return (1 & ((half - 1) >> 32)) - 1;
}

static u64 x16(const u8 a[16], const u8 b[16])
{
	return (load64_le(a + 0) ^ load64_le(b + 0))
		|  (load64_le(a + 8) ^ load64_le(b + 8));
}
static u64 x32(const u8 a[32],const u8 b[32]){ return x16(a,b) | x16(a+16, b+16); }
static int verify32(const u8 a[32], const u8 b[32]){ return neq0(x32(a, b)); }
static int zerocmp32(const u8 p[32]) { return verify32(p, zero); }

static const u64 iv[8] = {
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
};

// increment the input offset
static void blake2b_incr(blake2b_ctx *ctx)
{
	u64   *x = ctx->input_offset;
	size_t y = ctx->input_idx;
	x[0] += y;
	if (x[0] < y) {
		x[1]++;
	}
}

static void blake2b_compress(blake2b_ctx *ctx, int is_last_block)
{
	static const u8 sigma[12][16] = {
		{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
		{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
		{ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
		{  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
		{  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
		{  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
		{ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
		{ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
		{  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
		{ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
		{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
		{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
	};

	// init work vector
	u64 v0 = ctx->hash[0];  u64 v8  = iv[0];
	u64 v1 = ctx->hash[1];  u64 v9  = iv[1];
	u64 v2 = ctx->hash[2];  u64 v10 = iv[2];
	u64 v3 = ctx->hash[3];  u64 v11 = iv[3];
	u64 v4 = ctx->hash[4];  u64 v12 = iv[4] ^ ctx->input_offset[0];
	u64 v5 = ctx->hash[5];  u64 v13 = iv[5] ^ ctx->input_offset[1];
	u64 v6 = ctx->hash[6];  u64 v14 = iv[6] ^ (u64)~(is_last_block - 1);
	u64 v7 = ctx->hash[7];  u64 v15 = iv[7];

	// mangle work vector
	u64 *input = ctx->input;
#define BLAKE2_G(a, b, c, d, x, y)      \
	a += b + x;  d = rotr64(d ^ a, 32); \
	c += d;      b = rotr64(b ^ c, 24); \
	a += b + y;  d = rotr64(d ^ a, 16); \
	c += d;      b = rotr64(b ^ c, 63)
#define BLAKE2_ROUND(i)                                                 \
	BLAKE2_G(v0, v4, v8 , v12, input[sigma[i][ 0]], input[sigma[i][ 1]]); \
	BLAKE2_G(v1, v5, v9 , v13, input[sigma[i][ 2]], input[sigma[i][ 3]]); \
	BLAKE2_G(v2, v6, v10, v14, input[sigma[i][ 4]], input[sigma[i][ 5]]); \
	BLAKE2_G(v3, v7, v11, v15, input[sigma[i][ 6]], input[sigma[i][ 7]]); \
	BLAKE2_G(v0, v5, v10, v15, input[sigma[i][ 8]], input[sigma[i][ 9]]); \
	BLAKE2_G(v1, v6, v11, v12, input[sigma[i][10]], input[sigma[i][11]]); \
	BLAKE2_G(v2, v7, v8 , v13, input[sigma[i][12]], input[sigma[i][13]]); \
	BLAKE2_G(v3, v4, v9 , v14, input[sigma[i][14]], input[sigma[i][15]])

	FOR (i, 0, 12) {
		BLAKE2_ROUND(i);
	}

	// update hash
	ctx->hash[0] ^= v0 ^ v8;   ctx->hash[1] ^= v1 ^ v9;
	ctx->hash[2] ^= v2 ^ v10;  ctx->hash[3] ^= v3 ^ v11;
	ctx->hash[4] ^= v4 ^ v12;  ctx->hash[5] ^= v5 ^ v13;
	ctx->hash[6] ^= v6 ^ v14;  ctx->hash[7] ^= v7 ^ v15;
}

static void blake2b_set_input(blake2b_ctx *ctx, u8 input, size_t index)
{
	if (index == 0) {
		ZERO(ctx->input, 16);
	}
	size_t word = index >> 3;
	size_t byte = index & 7;
	ctx->input[word] |= (u64)input << (byte << 3);

}

static void blake2b_end_block(blake2b_ctx *ctx)
{
	if (ctx->input_idx == 128) {  // If buffer is full,
		blake2b_incr(ctx);        // update the input offset
		blake2b_compress(ctx, 0); // and compress the (not last) block
		ctx->input_idx = 0;
	}
}

static void blake2b_update_block(blake2b_ctx *ctx, const u8 *message, size_t message_size)
{
	FOR (i, 0, message_size) {
		blake2b_end_block(ctx);
		blake2b_set_input(ctx, message[i], ctx->input_idx);
		ctx->input_idx++;
	}
}

void blake2b_init(blake2b_ctx *ctx, size_t hash_size, const u8 *key, size_t key_size)
{
	// initial hash
	COPY(ctx->hash, iv, 8);
	ctx->hash[0] ^= 0x01010000 ^ (key_size << 8) ^ hash_size;

	ctx->input_offset[0] = 0;         // beginning of the input, no offset
	ctx->input_offset[1] = 0;         // beginning of the input, no offset
	ctx->hash_size       = hash_size; // remember the hash size we want
	ctx->input_idx       = 0;

	// if there is a key, the first block is that key (padded with zeroes)
	if (key_size > 0) {
		u8 key_block[128] = {0};
		COPY(key_block, key, key_size);
		// same as calling blake2b_update(ctx, key_block , 128)
		load64_le_buf(ctx->input, key_block, 16);
		ctx->input_idx = 128;
	}
}

void blake2b_update(blake2b_ctx *ctx, const void *message, size_t message_size)
{
	if (message_size == 0) {
		return;
	}
	// Align ourselves with block boundaries
	size_t aligned = MIN(align(ctx->input_idx, 128), message_size);
	blake2b_update_block(ctx, message, aligned);
	message      += aligned;
	message_size -= aligned;

	// Process the message block by block
	FOR (i, 0, message_size >> 7) { // number of blocks
		blake2b_end_block(ctx);
		load64_le_buf(ctx->input, message, 16);
		message += 128;
		ctx->input_idx = 128;
	}
	message_size &= 127;

	// remaining bytes
	blake2b_update_block(ctx, message, message_size);
}

void blake2b_final(blake2b_ctx *ctx, u8 *hash)
{
	// Pad the end of the block with zeroes
	FOR (i, ctx->input_idx, 128) {
		blake2b_set_input(ctx, 0, i);
	}
	blake2b_incr(ctx);        // update the input offset
	blake2b_compress(ctx, 1); // compress the last block
	size_t nb_words = ctx->hash_size >> 3;
	store64_le_buf(hash, ctx->hash, nb_words);
	FOR (i, nb_words << 3, ctx->hash_size) {
		hash[i] = (ctx->hash[i >> 3] >> (8 * (i & 7))) & 0xff;
	}
}

typedef struct {
	uint64_t hash[8];
	uint64_t input[16];
	uint64_t input_size[2];
	size_t   input_idx;
} sha512_ctx;

static u64 rot(u64 x, int c       ) { return (x >> c) | (x << (64 - c));   }
static u64 ch (u64 x, u64 y, u64 z) { return (x & y) ^ (~x & z);           }
static u64 maj(u64 x, u64 y, u64 z) { return (x & y) ^ ( x & z) ^ (y & z); }
static u64 big_sigma0(u64 x) { return rot(x, 28) ^ rot(x, 34) ^ rot(x, 39); }
static u64 big_sigma1(u64 x) { return rot(x, 14) ^ rot(x, 18) ^ rot(x, 41); }
static u64 lit_sigma0(u64 x) { return rot(x,  1) ^ rot(x,  8) ^ (x >> 7);   }
static u64 lit_sigma1(u64 x) { return rot(x, 19) ^ rot(x, 61) ^ (x >> 6);   }

static const u64 K[80] = {
	0x428a2f98d728ae22,0x7137449123ef65cd,0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc,
	0x3956c25bf348b538,0x59f111f1b605d019,0x923f82a4af194f9b,0xab1c5ed5da6d8118,
	0xd807aa98a3030242,0x12835b0145706fbe,0x243185be4ee4b28c,0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f,0x80deb1fe3b1696b1,0x9bdc06a725c71235,0xc19bf174cf692694,
	0xe49b69c19ef14ad2,0xefbe4786384f25e3,0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65,
	0x2de92c6f592b0275,0x4a7484aa6ea6e483,0x5cb0a9dcbd41fbd4,0x76f988da831153b5,
	0x983e5152ee66dfab,0xa831c66d2db43210,0xb00327c898fb213f,0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2,0xd5a79147930aa725,0x06ca6351e003826f,0x142929670a0e6e70,
	0x27b70a8546d22ffc,0x2e1b21385c26c926,0x4d2c6dfc5ac42aed,0x53380d139d95b3df,
	0x650a73548baf63de,0x766a0abb3c77b2a8,0x81c2c92e47edaee6,0x92722c851482353b,
	0xa2bfe8a14cf10364,0xa81a664bbc423001,0xc24b8b70d0f89791,0xc76c51a30654be30,
	0xd192e819d6ef5218,0xd69906245565a910,0xf40e35855771202a,0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8,0x1e376c085141ab53,0x2748774cdf8eeb99,0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb,0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc,0x78a5636f43172f60,0x84c87814a1f0ab72,0x8cc702081a6439ec,
	0x90befffa23631e28,0xa4506cebde82bde9,0xbef9a3f7b2c67915,0xc67178f2e372532b,
	0xca273eceea26619c,0xd186b8c721c0c207,0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178,
	0x06f067aa72176fba,0x0a637dc5a2c898a6,0x113f9804bef90dae,0x1b710b35131c471b,
	0x28db77f523047d84,0x32caab7b40c72493,0x3c9ebe0a15c9bebc,0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6,0x597f299cfc657e2a,0x5fcb6fab3ad6faec,0x6c44198c4a475817
};

static void sha512_compress(sha512_ctx *ctx)
{
	u64 a = ctx->hash[0];    u64 b = ctx->hash[1];
	u64 c = ctx->hash[2];    u64 d = ctx->hash[3];
	u64 e = ctx->hash[4];    u64 f = ctx->hash[5];
	u64 g = ctx->hash[6];    u64 h = ctx->hash[7];

	FOR (j, 0, 16) {
		u64 in = K[j] + ctx->input[j];
		u64 t1 = big_sigma1(e) + ch (e, f, g) + h + in;
		u64 t2 = big_sigma0(a) + maj(a, b, c);
		h = g;  g = f;  f = e;  e = d  + t1;
		d = c;  c = b;  b = a;  a = t1 + t2;
	}
	size_t i16 = 0;
	FOR(i, 1, 5) {
		i16 += 16;
		FOR (j, 0, 16) {
			ctx->input[j] += lit_sigma1(ctx->input[(j- 2) & 15]);
			ctx->input[j] += lit_sigma0(ctx->input[(j-15) & 15]);
			ctx->input[j] +=            ctx->input[(j- 7) & 15];
			u64 in = K[i16 + j] + ctx->input[j];
			u64 t1 = big_sigma1(e) + ch (e, f, g) + h + in;
			u64 t2 = big_sigma0(a) + maj(a, b, c);
			h = g;  g = f;  f = e;  e = d  + t1;
			d = c;  c = b;  b = a;  a = t1 + t2;
		}
	}

	ctx->hash[0] += a;    ctx->hash[1] += b;
	ctx->hash[2] += c;    ctx->hash[3] += d;
	ctx->hash[4] += e;    ctx->hash[5] += f;
	ctx->hash[6] += g;    ctx->hash[7] += h;
}

static void sha512_set_input(sha512_ctx *ctx, u8 input)
{
	if (ctx->input_idx == 0) {
		ZERO(ctx->input, 16);
	}
	size_t word = ctx->input_idx >> 3;
	size_t byte = ctx->input_idx &  7;
	ctx->input[word] |= (u64)input << (8 * (7 - byte));
}

// increment a 128-bit "word".
static void sha512_incr(u64 x[2], u64 y)
{
	x[1] += y;
	if (x[1] < y) {
		x[0]++;
	}
}

static void sha512_end_block(sha512_ctx *ctx)
{
	if (ctx->input_idx == 128) {
		sha512_incr(ctx->input_size, 1024); // size is in bits
		sha512_compress(ctx);
		ctx->input_idx = 0;
	}
}

static void sha512_update_block(sha512_ctx *ctx, const u8 *message, size_t message_size)
{
	FOR (i, 0, message_size) {
		sha512_set_input(ctx, message[i]);
		ctx->input_idx++;
		sha512_end_block(ctx);
	}
}

static void sha512_init(sha512_ctx *ctx)
{
	ctx->hash[0] = 0x6a09e667f3bcc908;
	ctx->hash[1] = 0xbb67ae8584caa73b;
	ctx->hash[2] = 0x3c6ef372fe94f82b;
	ctx->hash[3] = 0xa54ff53a5f1d36f1;
	ctx->hash[4] = 0x510e527fade682d1;
	ctx->hash[5] = 0x9b05688c2b3e6c1f;
	ctx->hash[6] = 0x1f83d9abfb41bd6b;
	ctx->hash[7] = 0x5be0cd19137e2179;
	ctx->input_size[0] = 0;
	ctx->input_size[1] = 0;
	ctx->input_idx = 0;
}

static void sha512_update(sha512_ctx *ctx, const u8 *message, size_t message_size)
{
	if (message_size == 0) {
		return;
	}
	// Align ourselves with block boundaries
	size_t aligned = MIN(align(ctx->input_idx, 128), message_size);
	sha512_update_block(ctx, message, aligned);
	message      += aligned;
	message_size -= aligned;

	// Process the message block by block
	FOR (i, 0, message_size / 128) { // number of blocks
		FOR (j, 0, 16) {
			ctx->input[j] = load64_be(message + j*8);
		}
		message        += 128;
		ctx->input_idx += 128;
		sha512_end_block(ctx);
	}
	message_size &= 127;

	// remaining bytes
	sha512_update_block(ctx, message, message_size);
}

static void sha512_final(sha512_ctx *ctx, u8 hash[64])
{
	sha512_incr(ctx->input_size, ctx->input_idx * 8); // size is in bits
	sha512_set_input(ctx, 128);                       // padding

	// compress penultimate block (if any)
	if (ctx->input_idx > 111) {
		sha512_compress(ctx);
		ZERO(ctx->input, 14);
	}
	// compress last block
	ctx->input[14] = ctx->input_size[0];
	ctx->input[15] = ctx->input_size[1];
	sha512_compress(ctx);

	// copy hash to output (big endian)
	FOR (i, 0, 8) {
		store64_be(hash + i*8, ctx->hash[i]);
	}
}

// field element
typedef i32 fe[10];

// field constants
//
// sqrtm1      : sqrt(-1)
// d           :     -121665 / 121666
// D2          : 2 * -121665 / 121666
// lop_x, lop_y: low order point in Edwards coordinates
// ufactor     : -sqrt(-1) * 2
// A2          : 486662^2  (A squared)
static const fe sqrtm1  = {-32595792, -7943725, 9377950, 3500415, 12389472,
			   -272473, -25146209, -2005654, 326686, 11406482,};
static const fe d       = {-10913610, 13857413, -15372611, 6949391, 114729,
			   -8787816, -6275908, -3247719, -18696448, -12055116,};
static const fe D2      = {-21827239, -5839606, -30745221, 13898782, 229458,
			   15978800, -12551817, -6495438, 29715968, 9444199,};

static void fe_0(fe h) {           ZERO(h  , 10); }
static void fe_1(fe h) { h[0] = 1; ZERO(h+1,  9); }

static void fe_copy(fe h,const fe f           ){FOR(i,0,10) h[i] =  f[i];      }
static void fe_neg (fe h,const fe f           ){FOR(i,0,10) h[i] = -f[i];      }
static void fe_add (fe h,const fe f,const fe g){FOR(i,0,10) h[i] = f[i] + g[i];}
static void fe_sub (fe h,const fe f,const fe g){FOR(i,0,10) h[i] = f[i] - g[i];}

static void fe_ccopy(fe f, const fe g, int b)
{
	i32 mask = -b; // -1 = 0xffffffff
	FOR (i, 0, 10) {
		i32 x = (f[i] ^ g[i]) & mask;
		f[i] = f[i] ^ x;
	}
}

#define FE_CARRY                                                        \
	i64 c0, c1, c2, c3, c4, c5, c6, c7, c8, c9;                         \
	c0 = (t0 + ((i64)1<<25)) >> 26; t1 += c0;      t0 -= c0 * ((i64)1 << 26); \
	c4 = (t4 + ((i64)1<<25)) >> 26; t5 += c4;      t4 -= c4 * ((i64)1 << 26); \
	c1 = (t1 + ((i64)1<<24)) >> 25; t2 += c1;      t1 -= c1 * ((i64)1 << 25); \
	c5 = (t5 + ((i64)1<<24)) >> 25; t6 += c5;      t5 -= c5 * ((i64)1 << 25); \
	c2 = (t2 + ((i64)1<<25)) >> 26; t3 += c2;      t2 -= c2 * ((i64)1 << 26); \
	c6 = (t6 + ((i64)1<<25)) >> 26; t7 += c6;      t6 -= c6 * ((i64)1 << 26); \
	c3 = (t3 + ((i64)1<<24)) >> 25; t4 += c3;      t3 -= c3 * ((i64)1 << 25); \
	c7 = (t7 + ((i64)1<<24)) >> 25; t8 += c7;      t7 -= c7 * ((i64)1 << 25); \
	c4 = (t4 + ((i64)1<<25)) >> 26; t5 += c4;      t4 -= c4 * ((i64)1 << 26); \
	c8 = (t8 + ((i64)1<<25)) >> 26; t9 += c8;      t8 -= c8 * ((i64)1 << 26); \
	c9 = (t9 + ((i64)1<<24)) >> 25; t0 += c9 * 19; t9 -= c9 * ((i64)1 << 25); \
	c0 = (t0 + ((i64)1<<25)) >> 26; t1 += c0;      t0 -= c0 * ((i64)1 << 26); \
	h[0]=(i32)t0;  h[1]=(i32)t1;  h[2]=(i32)t2;  h[3]=(i32)t3;  h[4]=(i32)t4; \
	h[5]=(i32)t5;  h[6]=(i32)t6;  h[7]=(i32)t7;  h[8]=(i32)t8;  h[9]=(i32)t9

static void fe_frombytes(fe h, const u8 s[32])
{
	i64 t0 =  load32_le(s);
	i64 t1 =  load24_le(s +  4) << 6;
	i64 t2 =  load24_le(s +  7) << 5;
	i64 t3 =  load24_le(s + 10) << 3;
	i64 t4 =  load24_le(s + 13) << 2;
	i64 t5 =  load32_le(s + 16);
	i64 t6 =  load24_le(s + 20) << 7;
	i64 t7 =  load24_le(s + 23) << 5;
	i64 t8 =  load24_le(s + 26) << 4;
	i64 t9 = (load24_le(s + 29) & 0x7fffff) << 2;
	FE_CARRY;
}

static void fe_tobytes(u8 s[32], const fe h)
{
	i32 t[10];
	COPY(t, h, 10);
	i32 q = (19 * t[9] + (((i32) 1) << 24)) >> 25;
	FOR (i, 0, 5) {
		q += t[2*i  ]; q >>= 26;
		q += t[2*i+1]; q >>= 25;
	}
	t[0] += 19 * q;
	q = 0;
	FOR (i, 0, 5) {
		t[i*2  ] += q;  q = t[i*2  ] >> 26;  t[i*2  ] -= q * ((i32)1 << 26);
		t[i*2+1] += q;  q = t[i*2+1] >> 25;  t[i*2+1] -= q * ((i32)1 << 25);
	}

	store32_le(s +  0, ((u32)t[0] >>  0) | ((u32)t[1] << 26));
	store32_le(s +  4, ((u32)t[1] >>  6) | ((u32)t[2] << 19));
	store32_le(s +  8, ((u32)t[2] >> 13) | ((u32)t[3] << 13));
	store32_le(s + 12, ((u32)t[3] >> 19) | ((u32)t[4] <<  6));
	store32_le(s + 16, ((u32)t[5] >>  0) | ((u32)t[6] << 25));
	store32_le(s + 20, ((u32)t[6] >>  7) | ((u32)t[7] << 19));
	store32_le(s + 24, ((u32)t[7] >> 13) | ((u32)t[8] << 12));
	store32_le(s + 28, ((u32)t[8] >> 20) | ((u32)t[9] <<  6));
}

// multiply a field element by a signed 32-bit integer
static void fe_mul_small(fe h, const fe f, i32 g)
{
	i64 t0 = f[0] * (i64) g;  i64 t1 = f[1] * (i64) g;
	i64 t2 = f[2] * (i64) g;  i64 t3 = f[3] * (i64) g;
	i64 t4 = f[4] * (i64) g;  i64 t5 = f[5] * (i64) g;
	i64 t6 = f[6] * (i64) g;  i64 t7 = f[7] * (i64) g;
	i64 t8 = f[8] * (i64) g;  i64 t9 = f[9] * (i64) g;
	FE_CARRY;
}

static void fe_mul(fe h, const fe f, const fe g)
{
	// Everything is unrolled and put in temporary variables.
	// We could roll the loop, but that would make curve25519 twice as slow.
	i32 f0 = f[0]; i32 f1 = f[1]; i32 f2 = f[2]; i32 f3 = f[3]; i32 f4 = f[4];
	i32 f5 = f[5]; i32 f6 = f[6]; i32 f7 = f[7]; i32 f8 = f[8]; i32 f9 = f[9];
	i32 g0 = g[0]; i32 g1 = g[1]; i32 g2 = g[2]; i32 g3 = g[3]; i32 g4 = g[4];
	i32 g5 = g[5]; i32 g6 = g[6]; i32 g7 = g[7]; i32 g8 = g[8]; i32 g9 = g[9];
	i32 F1 = f1*2; i32 F3 = f3*2; i32 F5 = f5*2; i32 F7 = f7*2; i32 F9 = f9*2;
	i32 G1 = g1*19;  i32 G2 = g2*19;  i32 G3 = g3*19;
	i32 G4 = g4*19;  i32 G5 = g5*19;  i32 G6 = g6*19;
	i32 G7 = g7*19;  i32 G8 = g8*19;  i32 G9 = g9*19;

	i64 t0 = f0*(i64)g0 + F1*(i64)G9 + f2*(i64)G8 + F3*(i64)G7 + f4*(i64)G6
		+    F5*(i64)G5 + f6*(i64)G4 + F7*(i64)G3 + f8*(i64)G2 + F9*(i64)G1;
	i64 t1 = f0*(i64)g1 + f1*(i64)g0 + f2*(i64)G9 + f3*(i64)G8 + f4*(i64)G7
		+    f5*(i64)G6 + f6*(i64)G5 + f7*(i64)G4 + f8*(i64)G3 + f9*(i64)G2;
	i64 t2 = f0*(i64)g2 + F1*(i64)g1 + f2*(i64)g0 + F3*(i64)G9 + f4*(i64)G8
		+    F5*(i64)G7 + f6*(i64)G6 + F7*(i64)G5 + f8*(i64)G4 + F9*(i64)G3;
	i64 t3 = f0*(i64)g3 + f1*(i64)g2 + f2*(i64)g1 + f3*(i64)g0 + f4*(i64)G9
		+    f5*(i64)G8 + f6*(i64)G7 + f7*(i64)G6 + f8*(i64)G5 + f9*(i64)G4;
	i64 t4 = f0*(i64)g4 + F1*(i64)g3 + f2*(i64)g2 + F3*(i64)g1 + f4*(i64)g0
		+    F5*(i64)G9 + f6*(i64)G8 + F7*(i64)G7 + f8*(i64)G6 + F9*(i64)G5;
	i64 t5 = f0*(i64)g5 + f1*(i64)g4 + f2*(i64)g3 + f3*(i64)g2 + f4*(i64)g1
		+    f5*(i64)g0 + f6*(i64)G9 + f7*(i64)G8 + f8*(i64)G7 + f9*(i64)G6;
	i64 t6 = f0*(i64)g6 + F1*(i64)g5 + f2*(i64)g4 + F3*(i64)g3 + f4*(i64)g2
		+    F5*(i64)g1 + f6*(i64)g0 + F7*(i64)G9 + f8*(i64)G8 + F9*(i64)G7;
	i64 t7 = f0*(i64)g7 + f1*(i64)g6 + f2*(i64)g5 + f3*(i64)g4 + f4*(i64)g3
		+    f5*(i64)g2 + f6*(i64)g1 + f7*(i64)g0 + f8*(i64)G9 + f9*(i64)G8;
	i64 t8 = f0*(i64)g8 + F1*(i64)g7 + f2*(i64)g6 + F3*(i64)g5 + f4*(i64)g4
		+    F5*(i64)g3 + f6*(i64)g2 + F7*(i64)g1 + f8*(i64)g0 + F9*(i64)G9;
	i64 t9 = f0*(i64)g9 + f1*(i64)g8 + f2*(i64)g7 + f3*(i64)g6 + f4*(i64)g5
		+    f5*(i64)g4 + f6*(i64)g3 + f7*(i64)g2 + f8*(i64)g1 + f9*(i64)g0;

	FE_CARRY;
}

// we could use fe_mul() for this, but this is significantly faster
static void fe_sq(fe h, const fe f)
{
	i32 f0 = f[0]; i32 f1 = f[1]; i32 f2 = f[2]; i32 f3 = f[3]; i32 f4 = f[4];
	i32 f5 = f[5]; i32 f6 = f[6]; i32 f7 = f[7]; i32 f8 = f[8]; i32 f9 = f[9];
	i32 f0_2  = f0*2;   i32 f1_2  = f1*2;   i32 f2_2  = f2*2;   i32 f3_2 = f3*2;
	i32 f4_2  = f4*2;   i32 f5_2  = f5*2;   i32 f6_2  = f6*2;   i32 f7_2 = f7*2;
	i32 f5_38 = f5*38;  i32 f6_19 = f6*19;  i32 f7_38 = f7*38;
	i32 f8_19 = f8*19;  i32 f9_38 = f9*38;

	i64 t0 = f0  *(i64)f0    + f1_2*(i64)f9_38 + f2_2*(i64)f8_19
		+    f3_2*(i64)f7_38 + f4_2*(i64)f6_19 + f5  *(i64)f5_38;
	i64 t1 = f0_2*(i64)f1    + f2  *(i64)f9_38 + f3_2*(i64)f8_19
		+    f4  *(i64)f7_38 + f5_2*(i64)f6_19;
	i64 t2 = f0_2*(i64)f2    + f1_2*(i64)f1    + f3_2*(i64)f9_38
		+    f4_2*(i64)f8_19 + f5_2*(i64)f7_38 + f6  *(i64)f6_19;
	i64 t3 = f0_2*(i64)f3    + f1_2*(i64)f2    + f4  *(i64)f9_38
		+    f5_2*(i64)f8_19 + f6  *(i64)f7_38;
	i64 t4 = f0_2*(i64)f4    + f1_2*(i64)f3_2  + f2  *(i64)f2
		+    f5_2*(i64)f9_38 + f6_2*(i64)f8_19 + f7  *(i64)f7_38;
	i64 t5 = f0_2*(i64)f5    + f1_2*(i64)f4    + f2_2*(i64)f3
		+    f6  *(i64)f9_38 + f7_2*(i64)f8_19;
	i64 t6 = f0_2*(i64)f6    + f1_2*(i64)f5_2  + f2_2*(i64)f4
		+    f3_2*(i64)f3    + f7_2*(i64)f9_38 + f8  *(i64)f8_19;
	i64 t7 = f0_2*(i64)f7    + f1_2*(i64)f6    + f2_2*(i64)f5
		+    f3_2*(i64)f4    + f8  *(i64)f9_38;
	i64 t8 = f0_2*(i64)f8    + f1_2*(i64)f7_2  + f2_2*(i64)f6
		+    f3_2*(i64)f5_2  + f4  *(i64)f4    + f9  *(i64)f9_38;
	i64 t9 = f0_2*(i64)f9    + f1_2*(i64)f8    + f2_2*(i64)f7
		+    f3_2*(i64)f6    + f4  *(i64)f5_2;

	FE_CARRY;
}

// h = 2 * (f^2)
static void fe_sq2(fe h, const fe f)
{
	fe_sq(h, f);
	fe_mul_small(h, h, 2);
}

// This could be simplified, but it would be slower
static void fe_pow22523(fe out, const fe z)
{
	fe t0, t1, t2;
	fe_sq(t0, z);
	fe_sq(t1,t0);                   fe_sq(t1, t1);  fe_mul(t1, z, t1);
	fe_mul(t0, t0, t1);
	fe_sq(t0, t0);                                  fe_mul(t0, t1, t0);
	fe_sq(t1, t0);  FOR (i, 1,   5) fe_sq(t1, t1);  fe_mul(t0, t1, t0);
	fe_sq(t1, t0);  FOR (i, 1,  10) fe_sq(t1, t1);  fe_mul(t1, t1, t0);
	fe_sq(t2, t1);  FOR (i, 1,  20) fe_sq(t2, t2);  fe_mul(t1, t2, t1);
	fe_sq(t1, t1);  FOR (i, 1,  10) fe_sq(t1, t1);  fe_mul(t0, t1, t0);
	fe_sq(t1, t0);  FOR (i, 1,  50) fe_sq(t1, t1);  fe_mul(t1, t1, t0);
	fe_sq(t2, t1);  FOR (i, 1, 100) fe_sq(t2, t2);  fe_mul(t1, t2, t1);
	fe_sq(t1, t1);  FOR (i, 1,  50) fe_sq(t1, t1);  fe_mul(t0, t1, t0);
	fe_sq(t0, t0);  FOR (i, 1,   2) fe_sq(t0, t0);  fe_mul(out, t0, z);
}

// Inverting means multiplying by 2^255 - 21
// 2^255 - 21 = (2^252 - 3) * 8 + 3
// So we reuse the multiplication chain of fe_pow22523
static void fe_invert(fe out, const fe z)
{
	fe tmp;
	fe_pow22523(tmp, z);
	// tmp2^8 * z^3
	fe_sq(tmp, tmp);                        // 0
	fe_sq(tmp, tmp);  fe_mul(tmp, tmp, z);  // 1
	fe_sq(tmp, tmp);  fe_mul(out, tmp, z);  // 1
}

//  Parity check.  Returns 0 if even, 1 if odd
static int fe_isodd(const fe f)
{
	u8 s[32];
	fe_tobytes(s, f);
	u8 isodd = s[0] & 1;
	return isodd;
}

// Returns 0 if zero, 1 if non zero
static int fe_isnonzero(const fe f)
{
	u8 s[32];
	fe_tobytes(s, f);
	int isnonzero = zerocmp32(s);
	return -isnonzero;
}

// Returns 1 if equal, 0 if not equal
static int fe_isequal(const fe f, const fe g)
{
	fe diff;
	fe_sub(diff, f, g);
	int isdifferent = fe_isnonzero(diff);
	return 1 - isdifferent;
}

// Inverse square root.
// Returns true if x is a non zero square, false otherwise.
// After the call:
//   isr = sqrt(1/x)        if x is non-zero square.
//   isr = sqrt(sqrt(-1)/x) if x is not a square.
//   isr = 0                if x is zero.
// We do not guarantee the sign of the square root.
//
// Notes:
// Let quartic = x^((p-1)/4)
//
// x^((p-1)/2) = chi(x)
// quartic^2   = chi(x)
// quartic     = sqrt(chi(x))
// quartic     = 1 or -1 or sqrt(-1) or -sqrt(-1)
//
// Note that x is a square if quartic is 1 or -1
// There are 4 cases to consider:
//
// if   quartic         = 1  (x is a square)
// then x^((p-1)/4)     = 1
//      x^((p-5)/4) * x = 1
//      x^((p-5)/4)     = 1/x
//      x^((p-5)/8)     = sqrt(1/x) or -sqrt(1/x)
//
// if   quartic                = -1  (x is a square)
// then x^((p-1)/4)            = -1
//      x^((p-5)/4) * x        = -1
//      x^((p-5)/4)            = -1/x
//      x^((p-5)/8)            = sqrt(-1)   / sqrt(x)
//      x^((p-5)/8) * sqrt(-1) = sqrt(-1)^2 / sqrt(x)
//      x^((p-5)/8) * sqrt(-1) = -1/sqrt(x)
//      x^((p-5)/8) * sqrt(-1) = -sqrt(1/x) or sqrt(1/x)
//
// if   quartic         = sqrt(-1)  (x is not a square)
// then x^((p-1)/4)     = sqrt(-1)
//      x^((p-5)/4) * x = sqrt(-1)
//      x^((p-5)/4)     = sqrt(-1)/x
//      x^((p-5)/8)     = sqrt(sqrt(-1)/x) or -sqrt(sqrt(-1)/x)
//
// Note that the product of two non-squares is always a square:
//   For any non-squares a and b, chi(a) = -1 and chi(b) = -1.
//   Since chi(x) = x^((p-1)/2), chi(a)*chi(b) = chi(a*b) = 1.
//   Therefore a*b is a square.
//
//   Since sqrt(-1) and x are both non-squares, their product is a
//   square, and we can compute their square root.
//
// if   quartic                = -sqrt(-1)  (x is not a square)
// then x^((p-1)/4)            = -sqrt(-1)
//      x^((p-5)/4) * x        = -sqrt(-1)
//      x^((p-5)/4)            = -sqrt(-1)/x
//      x^((p-5)/8)            = sqrt(-sqrt(-1)/x)
//      x^((p-5)/8)            = sqrt( sqrt(-1)/x) * sqrt(-1)
//      x^((p-5)/8) * sqrt(-1) = sqrt( sqrt(-1)/x) * sqrt(-1)^2
//      x^((p-5)/8) * sqrt(-1) = sqrt( sqrt(-1)/x) * -1
//      x^((p-5)/8) * sqrt(-1) = -sqrt(sqrt(-1)/x) or sqrt(sqrt(-1)/x)
static int invsqrt(fe isr, const fe x)
{
	fe check, quartic;
	fe_copy(check, x);
	fe_pow22523(isr, check);
	fe_sq (quartic, isr);
	fe_mul(quartic, quartic, check);
	fe_1  (check);          int p1 = fe_isequal(quartic, check);
	fe_neg(check, check );  int m1 = fe_isequal(quartic, check);
	fe_neg(check, sqrtm1);  int ms = fe_isequal(quartic, check);
	fe_mul(check, isr, sqrtm1);
	fe_ccopy(isr, check, m1 | ms);
	return p1 | m1;
}

// get bit from scalar at position i
static int scalar_bit(const u8 s[32], int i)
{
	if (i < 0) { return 0; } // handle -1 for sliding windows
	return (s[i>>3] >> (i&7)) & 1;
}

static const  u8 L[32] = {
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2,
	0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

// r = x mod L (little-endian)
static void modL(u8 *r, i64 x[64])
{
	for (unsigned i = 63; i >= 32; i--) {
		i64 carry = 0;
		FOR (j, i-32, i-12) {
			x[j] += carry - 16 * x[i] * L[j - (i - 32)];
			carry = (x[j] + 128) >> 8;
			x[j] -= carry * (1 << 8);
		}
		x[i-12] += carry;
		x[i] = 0;
	}
	i64 carry = 0;
	FOR (i, 0, 32) {
		x[i] += carry - (x[31] >> 4) * L[i];
		carry = x[i] >> 8;
		x[i] &= 255;
	}
	FOR (i, 0, 32) {
		x[i] -= carry * L[i];
	}
	FOR (i, 0, 32) {
		x[i+1] += x[i] >> 8;
		r[i  ]  = x[i] & 255;
	}
}

// Reduces a 64-byte hash modulo L (little endian)
static void reduce(u8 r[64])
{
	i64 x[64];
	COPY(x, r, 64);
	modL(r, x);
}

// Variable time! a must not be secret!
static int is_above_L(const u8 a[32])
{
	for (int i = 31; i >= 0; i--) {
		if (a[i] > L[i]) { return 1; }
		if (a[i] < L[i]) { return 0; }
	}
	return 1;
}

// Point (group element, ge) in a twisted Edwards curve,
// in extended projective coordinates.
// ge        : x  = X/Z, y  = Y/Z, T  = XY/Z
// ge_cached : Yp = X+Y, Ym = X-Y, T2 = T*D2
// ge_precomp: Z  = 1
typedef struct { fe X;  fe Y;  fe Z; fe T;  } ge;
typedef struct { fe Yp; fe Ym; fe Z; fe T2; } ge_cached;
typedef struct { fe Yp; fe Ym;       fe T2; } ge_precomp;

static void ge_zero(ge *p)
{
	fe_0(p->X);
	fe_1(p->Y);
	fe_1(p->Z);
	fe_0(p->T);
}

static void ge_tobytes(u8 s[32], const ge *h)
{
	fe recip, x, y;
	fe_invert(recip, h->Z);
	fe_mul(x, h->X, recip);
	fe_mul(y, h->Y, recip);
	fe_tobytes(s, y);
	s[31] ^= fe_isodd(x) << 7;
}

// h = s, where s is a point encoded in 32 bytes
//
// Variable time!  Inputs must not be secret!
// => Use only to *check* signatures.
//
// From the specifications:
//   The encoding of s contains y and the sign of x
//   x = sqrt((y^2 - 1) / (d*y^2 + 1))
// In extended coordinates:
//   X = x, Y = y, Z = 1, T = x*y
//
//    Note that num * den is a square iff num / den is a square
//    If num * den is not a square, the point was not on the curve.
// From the above:
//   Let num =   y^2 - 1
//   Let den = d*y^2 + 1
//   x = sqrt((y^2 - 1) / (d*y^2 + 1))
//   x = sqrt(num / den)
//   x = sqrt(num^2 / (num * den))
//   x = num * sqrt(1 / (num * den))
//
// Therefore, we can just compute:
//   num =   y^2 - 1
//   den = d*y^2 + 1
//   isr = invsqrt(num * den)  // abort if not square
//   x   = num * isr
// Finally, negate x if its sign is not as specified.
static int ge_frombytes_vartime(ge *h, const u8 s[32])
{
	fe_frombytes(h->Y, s);
	fe_1(h->Z);
	fe_sq (h->T, h->Y);        // t =   y^2
	fe_mul(h->X, h->T, d   );  // x = d*y^2
	fe_sub(h->T, h->T, h->Z);  // t =   y^2 - 1
	fe_add(h->X, h->X, h->Z);  // x = d*y^2 + 1
	fe_mul(h->X, h->T, h->X);  // x = (y^2 - 1) * (d*y^2 + 1)
	int is_square = invsqrt(h->X, h->X);
	if (!is_square) {
		return -1;             // Not on the curve, abort
	}
	fe_mul(h->X, h->T, h->X);  // x = sqrt((y^2 - 1) / (d*y^2 + 1))
	if (fe_isodd(h->X) != (s[31] >> 7)) {
		fe_neg(h->X, h->X);
	}
	fe_mul(h->T, h->X, h->Y);
	return 0;
}

static void ge_cache(ge_cached *c, const ge *p)
{
	fe_add (c->Yp, p->Y, p->X);
	fe_sub (c->Ym, p->Y, p->X);
	fe_copy(c->Z , p->Z      );
	fe_mul (c->T2, p->T, D2  );
}

// Internal buffers are not wiped! Inputs must not be secret!
// => Use only to *check* signatures.
static void ge_add(ge *s, const ge *p, const ge_cached *q)
{
	fe a, b;
	fe_add(a   , p->Y, p->X );
	fe_sub(b   , p->Y, p->X );
	fe_mul(a   , a   , q->Yp);
	fe_mul(b   , b   , q->Ym);
	fe_add(s->Y, a   , b    );
	fe_sub(s->X, a   , b    );

	fe_add(s->Z, p->Z, p->Z );
	fe_mul(s->Z, s->Z, q->Z );
	fe_mul(s->T, p->T, q->T2);
	fe_add(a   , s->Z, s->T );
	fe_sub(b   , s->Z, s->T );

	fe_mul(s->T, s->X, s->Y);
	fe_mul(s->X, s->X, b   );
	fe_mul(s->Y, s->Y, a   );
	fe_mul(s->Z, a   , b   );
}

// Internal buffers are not wiped! Inputs must not be secret!
// => Use only to *check* signatures.
static void ge_sub(ge *s, const ge *p, const ge_cached *q)
{
	ge_cached neg;
	fe_copy(neg.Ym, q->Yp);
	fe_copy(neg.Yp, q->Ym);
	fe_copy(neg.Z , q->Z );
	fe_neg (neg.T2, q->T2);
	ge_add(s, p, &neg);
}

static void ge_madd(ge *s, const ge *p, const ge_precomp *q, fe a, fe b)
{
	fe_add(a   , p->Y, p->X );
	fe_sub(b   , p->Y, p->X );
	fe_mul(a   , a   , q->Yp);
	fe_mul(b   , b   , q->Ym);
	fe_add(s->Y, a   , b    );
	fe_sub(s->X, a   , b    );

	fe_add(s->Z, p->Z, p->Z );
	fe_mul(s->T, p->T, q->T2);
	fe_add(a   , s->Z, s->T );
	fe_sub(b   , s->Z, s->T );

	fe_mul(s->T, s->X, s->Y);
	fe_mul(s->X, s->X, b   );
	fe_mul(s->Y, s->Y, a   );
	fe_mul(s->Z, a   , b   );
}

static void ge_msub(ge *s, const ge *p, const ge_precomp *q, fe a, fe b)
{
	fe_add(a   , p->Y, p->X );
	fe_sub(b   , p->Y, p->X );
	fe_mul(a   , a   , q->Ym);
	fe_mul(b   , b   , q->Yp);
	fe_add(s->Y, a   , b    );
	fe_sub(s->X, a   , b    );

	fe_add(s->Z, p->Z, p->Z );
	fe_mul(s->T, p->T, q->T2);
	fe_sub(a   , s->Z, s->T );
	fe_add(b   , s->Z, s->T );

	fe_mul(s->T, s->X, s->Y);
	fe_mul(s->X, s->X, b   );
	fe_mul(s->Y, s->Y, a   );
	fe_mul(s->Z, a   , b   );
}

static void ge_double(ge *s, const ge *p, ge *q)
{
	fe_sq (q->X, p->X);
	fe_sq (q->Y, p->Y);
	fe_sq2(q->Z, p->Z);
	fe_add(q->T, p->X, p->Y);
	fe_sq (s->T, q->T);
	fe_add(q->T, q->Y, q->X);
	fe_sub(q->Y, q->Y, q->X);
	fe_sub(q->X, s->T, q->T);
	fe_sub(q->Z, q->Z, q->Y);

	fe_mul(s->X, q->X , q->Z);
	fe_mul(s->Y, q->T , q->Y);
	fe_mul(s->Z, q->Y , q->Z);
	fe_mul(s->T, q->X , q->T);
}

// 5-bit signed window in cached format (Niels coordinates, Z=1)
static const ge_precomp b_window[8] = {
	{{25967493,-14356035,29566456,3660896,-12694345,
	  4014787,27544626,-11754271,-6079156,2047605,},
	 {-12545711,934262,-2722910,3049990,-727428,
	  9406986,12720692,5043384,19500929,-15469378,},
	 {-8738181,4489570,9688441,-14785194,10184609,
	  -12363380,29287919,11864899,-24514362,-4438546,},},
	{{15636291,-9688557,24204773,-7912398,616977,
	  -16685262,27787600,-14772189,28944400,-1550024,},
	 {16568933,4717097,-11556148,-1102322,15682896,
	  -11807043,16354577,-11775962,7689662,11199574,},
	 {30464156,-5976125,-11779434,-15670865,23220365,
	  15915852,7512774,10017326,-17749093,-9920357,},},
	{{10861363,11473154,27284546,1981175,-30064349,
	  12577861,32867885,14515107,-15438304,10819380,},
	 {4708026,6336745,20377586,9066809,-11272109,
	  6594696,-25653668,12483688,-12668491,5581306,},
	 {19563160,16186464,-29386857,4097519,10237984,
	  -4348115,28542350,13850243,-23678021,-15815942,},},
	{{5153746,9909285,1723747,-2777874,30523605,
	  5516873,19480852,5230134,-23952439,-15175766,},
	 {-30269007,-3463509,7665486,10083793,28475525,
	  1649722,20654025,16520125,30598449,7715701,},
	 {28881845,14381568,9657904,3680757,-20181635,
	  7843316,-31400660,1370708,29794553,-1409300,},},
	{{-22518993,-6692182,14201702,-8745502,-23510406,
	  8844726,18474211,-1361450,-13062696,13821877,},
	 {-6455177,-7839871,3374702,-4740862,-27098617,
	  -10571707,31655028,-7212327,18853322,-14220951,},
	 {4566830,-12963868,-28974889,-12240689,-7602672,
	  -2830569,-8514358,-10431137,2207753,-3209784,},},
	{{-25154831,-4185821,29681144,7868801,-6854661,
	  -9423865,-12437364,-663000,-31111463,-16132436,},
	 {25576264,-2703214,7349804,-11814844,16472782,
	  9300885,3844789,15725684,171356,6466918,},
	 {23103977,13316479,9739013,-16149481,817875,
	  -15038942,8965339,-14088058,-30714912,16193877,},},
	{{-33521811,3180713,-2394130,14003687,-16903474,
	  -16270840,17238398,4729455,-18074513,9256800,},
	 {-25182317,-4174131,32336398,5036987,-21236817,
	  11360617,22616405,9761698,-19827198,630305,},
	 {-13720693,2639453,-24237460,-7406481,9494427,
	  -5774029,-6554551,-15960994,-2449256,-14291300,},},
	{{-3151181,-5046075,9282714,6866145,-31907062,
	  -863023,-18940575,15033784,25105118,-7894876,},
	 {-24326370,15950226,-31801215,-14592823,-11662737,
	  -5090925,1573892,-2625887,2198790,-15804619,},
	 {-3099351,10324967,-2241613,7453183,-5446979,
	  -2735503,-13812022,-16236442,-32461234,-12290683,},},
};

// Incremental sliding windows (left to right)
// Based on Roberto Maria Avanzi[2005]
typedef struct {
	i16 next_index; // position of the next signed digit
	i8  next_digit; // next signed digit (odd number below 2^window_width)
	u8  next_check; // point at which we must check for a new window
} slide_ctx;

static void slide_init(slide_ctx *ctx, const u8 scalar[32])
{
	// scalar is guaranteed to be below L, either because we checked (s),
	// or because we reduced it modulo L (h_ram). L is under 2^253, so
	// so bits 253 to 255 are guaranteed to be zero. No need to test them.
	//
	// Note however that L is very close to 2^252, so bit 252 is almost
	// always zero.  If we were to start at bit 251, the tests wouldn't
	// catch the off-by-one error (constructing one that does would be
	// prohibitively expensive).
	//
	// We should still check bit 252, though.
	int i = 252;
	while (i > 0 && scalar_bit(scalar, i) == 0) {
		i--;
	}
	ctx->next_check = (u8)(i + 1);
	ctx->next_index = -1;
	ctx->next_digit = -1;
}

static int slide_step(slide_ctx *ctx, int width, int i, const u8 scalar[32])
{
	if (i == ctx->next_check) {
		if (scalar_bit(scalar, i) == scalar_bit(scalar, i - 1)) {
			ctx->next_check--;
		} else {
			// compute digit of next window
			int w = MIN(width, i + 1);
			int v = -(scalar_bit(scalar, i) << (w-1));
			FOR_T (int, j, 0, w-1) {
				v += scalar_bit(scalar, i-(w-1)+j) << j;
			}
			v += scalar_bit(scalar, i-w);
			int lsb = v & (~v + 1);            // smallest bit of v
			int s   = (   ((lsb & 0xAA) != 0)  // log2(lsb)
					   | (((lsb & 0xCC) != 0) << 1)
					   | (((lsb & 0xF0) != 0) << 2));
			ctx->next_index  = (i16)(i-(w-1)+s);
			ctx->next_digit  = (i8) (v >> s   );
			ctx->next_check -= w;
		}
	}
	return i == ctx->next_index ? ctx->next_digit: 0;
}

#define P_W_WIDTH 3 // Affects the size of the stack
#define B_W_WIDTH 5 // Affects the size of the binary
#define P_W_SIZE  (1<<(P_W_WIDTH-2))

// P = [b]B + [p]P, where B is the base point
//
// Variable time! Internal buffers are not wiped! Inputs must not be secret!
// => Use only to *check* signatures.
static void ge_double_scalarmult_vartime(ge *P, const u8 p[32], const u8 b[32])
{
	// cache P window for addition
	ge_cached cP[P_W_SIZE];
	{
		ge P2, tmp;
		ge_double(&P2, P, &tmp);
		ge_cache(&cP[0], P);
		FOR (i, 1, P_W_SIZE) {
			ge_add(&tmp, &P2, &cP[i-1]);
			ge_cache(&cP[i], &tmp);
		}
	}

	// Merged double and add ladder, fused with sliding
	slide_ctx p_slide;  slide_init(&p_slide, p);
	slide_ctx b_slide;  slide_init(&b_slide, b);
	int i = MAX(p_slide.next_check, b_slide.next_check);
	ge *sum = P;
	ge_zero(sum);
	while (i >= 0) {
		ge tmp;
		ge_double(sum, sum, &tmp);
		int p_digit = slide_step(&p_slide, P_W_WIDTH, i, p);
		int b_digit = slide_step(&b_slide, B_W_WIDTH, i, b);
		if (p_digit > 0) { ge_add(sum, sum, &cP[ p_digit / 2]); }
		if (p_digit < 0) { ge_sub(sum, sum, &cP[-p_digit / 2]); }
		fe t1, t2;
		if (b_digit > 0) { ge_madd(sum, sum, b_window +  b_digit/2, t1, t2); }
		if (b_digit < 0) { ge_msub(sum, sum, b_window + -b_digit/2, t1, t2); }
		i--;
	}
}

// R_check = s[B] - h_ram[pk], where B is the base point
//
// Variable time! Internal buffers are not wiped! Inputs must not be secret!
// => Use only to *check* signatures.
static int ge_r_check(u8 R_check[32], const u8 s[32], const u8 h_ram[32], const u8 pk[32])
{
	ge A; // not secret, not wiped
	if (ge_frombytes_vartime(&A, pk) ||         // A = pk
		is_above_L(s)) {                    // prevent s malleability
		return -1;
	}
	fe_neg(A.X, A.X);
	fe_neg(A.T, A.T);                           // A = -pk
	ge_double_scalarmult_vartime(&A, h_ram, s); // A = [s]B - [h_ram]pk
	ge_tobytes(R_check, &A);                    // R_check = A
	return 0;
}

bool ed25519_verify(const u8 signature[64], const u8 public_key[32],
		    const void *message, size_t message_size)
{
	sha512_ctx hash;
	u8 h_ram[64];
	u8 R_check[32];

	sha512_init(&hash);
	sha512_update(&hash, signature, 32);
	sha512_update(&hash, public_key, 32);
	sha512_update(&hash, message, message_size);
	sha512_final(&hash, h_ram);

	reduce(h_ram);
	if (ge_r_check(R_check, signature + 32, h_ram, public_key))
		return false;
	return verify32(signature, R_check) == 0 ? true : false;
}
