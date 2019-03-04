/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

#ifndef CONFVIEW_H
#define CONFVIEW_H

#include <stdbool.h>
#include <windows.h>
#include <richedit.h>

#define CONFVIEW_STYLE (WS_CHILD | WS_CLIPSIBLINGS | ES_MULTILINE | WS_VISIBLE | WS_VSCROLL | ES_READONLY | WS_TABSTOP | ES_WANTRETURN | ES_NOOLEDRAGDROP)
#define CONFVIEW_EXTSTYLE (WS_EX_TRANSPARENT)

#define PV_NEWRTF (WM_USER + 0x3200)

extern bool register_conf_view(void);

#endif
