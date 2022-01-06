/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2020-2021 Jason A. Donenfeld. All Rights Reserved.
 */

#ifndef _CRYPTO_H
#define _CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

struct blake2b256_state {
	uint64_t h[8];
	uint64_t t[2];
	uint64_t f[2];
	uint8_t buf[128];
	size_t buflen;
};

void blake2b256_init(struct blake2b256_state *state);
void blake2b256_update(struct blake2b256_state *state, const uint8_t *in,
		       unsigned int inlen);
void blake2b256_final(struct blake2b256_state *state, uint8_t out[32]);

bool ed25519_verify(const uint8_t signature[64], const uint8_t public_key[32],
		    const void *message, size_t message_size);

#endif
