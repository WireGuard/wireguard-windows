/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (c) 2017-2020, Loup Vaillant. All rights reserved.
 * Copyright (C) 2020 Jason A. Donenfeld. All Rights Reserved.
 */

#ifndef _CRYPTO_H
#define _CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct {
	uint64_t hash[8];
	uint64_t input_offset[2];
	uint64_t input[16];
	size_t   input_idx;
	size_t   hash_size;
} blake2b_ctx;

void blake2b_init(blake2b_ctx *ctx, size_t hash_size, const uint8_t *key, size_t key_size);

void blake2b_update(blake2b_ctx *ctx, const void *message, size_t message_size);

void blake2b_final(blake2b_ctx *ctx, uint8_t *hash);

bool ed25519_verify(const uint8_t signature[64], const uint8_t public_key[32],
		    const void *message, size_t message_size);

#endif
