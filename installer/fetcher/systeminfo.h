/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2020-2022 Jason A. Donenfeld. All Rights Reserved.
 */

#ifndef _SYSTEMINFO_H
#define _SYSTEMINFO_H

#include <stdbool.h>

const char *architecture(void);
const char *useragent(void);
bool is_win7(void);
bool is_win8dotzero_or_below(void);

#endif
