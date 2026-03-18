// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2026 Jason A. Donenfeld. All Rights Reserved.
 *
 * This here is a bit of a hack. We're compiling with subsystem=10.0 in the PE
 * header, and so the Windows loader expects to see either
 * _load_config.SecurityCookie set to the initial magic value, or for
 * IMAGE_GUARD_SECURITY_COOKIE_UNUSED to be set. libssp doesn't use
 * SecurityCookie anyway; SecurityCookie is for MSVC's /GS protection. So it
 * seems like the proper thing to do is signal to the OS that it doesn't need
 * to initialize SecurityCookie.
 */

#include <windows.h>

#define IMAGE_GUARD_SECURITY_COOKIE_UNUSED 0x00000800
const IMAGE_LOAD_CONFIG_DIRECTORY _load_config_used = {
	.Size = sizeof(_load_config_used),
	.GuardFlags = IMAGE_GUARD_SECURITY_COOKIE_UNUSED
};
