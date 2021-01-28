/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2020-2021 Jason A. Donenfeld. All Rights Reserved.
 */

#ifndef _FILELIST_H
#define _FILELIST_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

enum { MAX_FILENAME_LEN = 0x400 };

bool extract_newest_file(char filename[static MAX_FILENAME_LEN], uint8_t hash[static 32], const char *list, size_t len, const char *arch);

#endif
