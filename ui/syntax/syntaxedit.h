/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

#ifndef SYNTAXEDIT_H
#define SYNTAXEDIT_H

#include <stdbool.h>
#include <windows.h>
#include <richedit.h>

#define SYNTAXEDIT_STYLE (WS_CHILD | ES_MULTILINE | WS_VISIBLE | WS_VSCROLL | WS_BORDER | WS_HSCROLL | WS_TABSTOP | ES_WANTRETURN | ES_NOOLEDRAGDROP)
#define SYNTAXEDIT_EXTSTYLE (0)

/* The old MFC reflection trick. */
#define WM_REFLECT (WM_USER + 0x1C00)

#define SE_PRIVATE_KEY (WM_USER + 0x3100)
#define SE_TRAFFIC_BLOCK (WM_USER + 0x3101)
#define SE_SET_PARENT_DPI (WM_USER + 0x3102)

enum block_state {
	InevaluableBlockingUntunneledTraffic,
	BlockingUntunneledTraffic,
	NotBlockingUntunneledTraffic
};

extern bool register_syntax_edit(void);

#endif
