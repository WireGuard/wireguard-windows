// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Jason A. Donenfeld. All Rights Reserved.
 */

#include "constants.h"
#include "crypto.h"
#include "filelist.h"
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static inline int decode_base64(const char src[static 4])
{
	int val = 0;

	for (unsigned int i = 0; i < 4; ++i)
		val |= (-1
			    + ((((('A' - 1) - src[i]) & (src[i] - ('Z' + 1))) >> 8) & (src[i] - 64))
			    + ((((('a' - 1) - src[i]) & (src[i] - ('z' + 1))) >> 8) & (src[i] - 70))
			    + ((((('0' - 1) - src[i]) & (src[i] - ('9' + 1))) >> 8) & (src[i] + 5))
			    + ((((('+' - 1) - src[i]) & (src[i] - ('+' + 1))) >> 8) & 63)
			    + ((((('/' - 1) - src[i]) & (src[i] - ('/' + 1))) >> 8) & 64)
			) << (18 - 6 * i);
	return val;
}

bool signify_pubkey_from_base64(uint8_t key[static 42], const char base64[static 56])
{
	unsigned int i;
	volatile uint8_t ret = 0;
	int val;

	for (i = 0; i < 42 / 3; ++i) {
		val = decode_base64(&base64[i * 4]);
		ret |= (uint32_t)val >> 31;
		key[i * 3 + 0] = (val >> 16) & 0xff;
		key[i * 3 + 1] = (val >> 8) & 0xff;
		key[i * 3 + 2] = val & 0xff;
	}

	return 1 & ((ret - 1) >> 8);
}

bool signify_signature_from_base64(uint8_t sig[static 74], const char base64[static 100])
{
	unsigned int i;
	volatile uint8_t ret = 0;
	int val;

	if (base64[99] != '=')
		return false;

	for (i = 0; i < 74 / 3; ++i) {
		val = decode_base64(&base64[i * 4]);
		ret |= (uint32_t)val >> 31;
		sig[i * 3 + 0] = (val >> 16) & 0xff;
		sig[i * 3 + 1] = (val >> 8) & 0xff;
		sig[i * 3 + 2] = val & 0xff;
	}
	val = decode_base64((const char[]){ base64[i * 4 + 0], base64[i * 4 + 1], base64[i * 4 + 2], 'A' });
	ret |= ((uint32_t)val >> 31) | (val & 0xff);
	sig[i * 3 + 0] = (val >> 16) & 0xff;
	sig[i * 3 + 1] = (val >> 8) & 0xff;

	return 1 & ((ret - 1) >> 8);
}

bool hash_from_hex(uint8_t hash[static 32], const char hex[static 64])
{
	uint8_t c, c_acc, c_alpha0, c_alpha, c_num0, c_num, c_val;
	volatile uint8_t ret = 0;

	for (unsigned int i = 0; i < 64; i += 2) {
		c = (uint8_t)hex[i];
		c_num = c ^ 48U;
		c_num0 = (c_num - 10U) >> 8;
		c_alpha = (c & ~32U) - 55U;
		c_alpha0 = ((c_alpha - 10U) ^ (c_alpha - 16U)) >> 8;
		ret |= ((c_num0 | c_alpha0) - 1) >> 8;
		c_val = (c_num0 & c_num) | (c_alpha0 & c_alpha);
		c_acc = c_val * 16U;

		c = (uint8_t)hex[i + 1];
		c_num = c ^ 48U;
		c_num0 = (c_num - 10U) >> 8;
		c_alpha = (c & ~32U) - 55U;
		c_alpha0 = ((c_alpha - 10U) ^ (c_alpha - 16U)) >> 8;
		ret |= ((c_num0 | c_alpha0) - 1) >> 8;
		c_val = (c_num0 & c_num) | (c_alpha0 & c_alpha);
		hash[i / 2] = c_acc | c_val;
	}

	return 1 & ((ret - 1) >> 8);
}

static uint64_t parse_version(const char *str, size_t len)
{
	uint64_t version = 0;
	unsigned long nibble;
	const char *limit = str + len;
	char *end;

	for (int shift = 64 - 16; shift >= 0; shift -= 16, str = end + 1) {
		if (str[0] == '-' || str[0] == '+')
			return 0;
		nibble = strtoul(str, &end, 10);
		if (nibble > UINT16_MAX)
			return 0;
		version |= (uint64_t)nibble << shift;
		if (end >= limit)
			break;
		if (end[0] != '.')
			return 0;
	}
	return version;
}

bool extract_newest_file(char filename[static MAX_FILENAME_LEN], uint8_t hash[static 32], const char *list, size_t len, const char *arch)
{
	const char *first_nl, *second_nl, *line_start, *line_end;
	char msi_prefix[sizeof(msi_arch_prefix) + 10];
	size_t msi_prefix_len;
	uint8_t pubkey[42], signature[74];
	uint64_t biggest_version = 0, version;

	if ((msi_prefix_len = snprintf(msi_prefix, sizeof(msi_prefix), msi_arch_prefix, arch)) >= sizeof(msi_prefix))
		return false;
	if (!signify_pubkey_from_base64(pubkey, release_public_key_base64))
		return false;
	first_nl = memchr(list, '\n', len);
	if (!first_nl)
		return false;
	second_nl = memchr(first_nl + 1, '\n', len - (first_nl + 1 - list));
	if (!second_nl)
		return false;
	if (len < 19 || memcmp(list, "untrusted comment: ", 19))
		return false;
	if (second_nl - first_nl != 101)
		return false;
	if (!signify_signature_from_base64(signature, first_nl + 1))
		return false;
	if (memcmp(pubkey, signature, 10))
		return false;
	if (!ed25519_verify(signature + 10, pubkey + 10, second_nl + 1, len - (second_nl + 1 - list)))
		return false;
	for (line_start = second_nl + 1; line_start < list + len; line_start = line_end + 1) {
		line_end = memchr(line_start + 1, '\n', len - (line_start + 1 - list));
		if (!line_end)
			break;
		if ((size_t)(line_end - line_start) < (64 + 2 + msi_prefix_len + strlen(msi_suffix) + 1) || line_start[64] != ' ' || line_start[65] != ' ')
			continue;
		if (memcmp(msi_prefix, line_start + 66, msi_prefix_len) || memcmp(msi_suffix, line_end - strlen(msi_suffix), strlen(msi_suffix)))
			continue;
		if (line_end - line_start - 66 > MAX_FILENAME_LEN - 1)
			continue;
		version = parse_version(line_start + 66 + msi_prefix_len, line_end - strlen(msi_suffix) - line_start - 66 - msi_prefix_len);
		if (version < biggest_version)
			continue;
		if (!hash_from_hex(hash, line_start))
			continue;
		memcpy(filename, line_start + 66, line_end - line_start - 66);
		filename[line_end - line_start - 66] = '\0';
		biggest_version = version;
	}
	return biggest_version > 0;
}
