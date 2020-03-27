/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <windows.h>
#include <windowsx.h>
#include <richedit.h>
#include <richole.h>
#include <tom.h>

#include "syntaxedit.h"
#include "highlighter.h"

const GUID CDECL IID_ITextDocument = { 0x8CC497C0, 0xA1DF, 0x11CE, { 0x80, 0x98, 0x00, 0xAA, 0x00, 0x47, 0xBE, 0x5D } };

struct syntaxedit_data {
	IRichEditOle *irich;
	ITextDocument *idoc;
	enum block_state last_block_state;
	LONG yheight;
	bool highlight_guard;
};

static WNDPROC parent_proc;

struct span_style {
	COLORREF color;
	DWORD effects;
};

static const struct span_style stylemap[] = {
	[HighlightSection] = { .color = RGB(0x32, 0x6D, 0x74), .effects = CFE_BOLD },
	[HighlightField] = { .color = RGB(0x9B, 0x23, 0x93), .effects = CFE_BOLD },
	[HighlightPrivateKey] = { .color = RGB(0x64, 0x38, 0x20) },
	[HighlightPublicKey] = { .color = RGB(0x64, 0x38, 0x20) },
	[HighlightPresharedKey] = { .color = RGB(0x64, 0x38, 0x20) },
	[HighlightIP] = { .color = RGB(0x0E, 0x0E, 0xFF) },
	[HighlightCidr] = { .color = RGB(0x81, 0x5F, 0x03) },
	[HighlightHost] = { .color = RGB(0x0E, 0x0E, 0xFF) },
	[HighlightPort] = { .color = RGB(0x81, 0x5F, 0x03) },
	[HighlightMTU] = { .color = RGB(0x1C, 0x00, 0xCF) },
	[HighlightMetric] = { .color = RGB(0x1C, 0x00, 0xCF) },
	[HighlightKeepalive] = { .color = RGB(0x1C, 0x00, 0xCF) },
	[HighlightComment] = { .color = RGB(0x53, 0x65, 0x79), .effects = CFE_ITALIC },
	[HighlightDelimiter] = { .color = RGB(0x00, 0x00, 0x00) },
#ifndef MOBILE_WGQUICK_SUBSET
	[HighlightTable] = { .color = RGB(0x1C, 0x00, 0xCF) },
	[HighlightFwMark] = { .color = RGB(0x1C, 0x00, 0xCF) },
	[HighlightSaveConfig] = { .color = RGB(0x81, 0x5F, 0x03) },
	[HighlightCmd] = { .color = RGB(0x63, 0x75, 0x89) },
#endif
	[HighlightError] = { .color = RGB(0xC4, 0x1A, 0x16), .effects = CFE_UNDERLINE }
};

static void evaluate_untunneled_blocking(struct syntaxedit_data *this, HWND hWnd, const char *msg, struct highlight_span *spans)
{
	enum block_state state = InevaluableBlockingUntunneledTraffic;
	bool on_allowedips = false;
	bool seen_peer = false;
	bool seen_v6_00 = false, seen_v4_00 = false;
	bool seen_v6_01 = false, seen_v6_80001 = false, seen_v4_01 = false, seen_v4_1281 = false;

	for (struct highlight_span *span = spans; span->type != HighlightEnd; ++span) {
		switch (span->type) {
		case HighlightError:
			goto done;
		case HighlightSection:
			if (span->len != 6 || strncasecmp(&msg[span->start], "[peer]", 6))
				break;
			if (!seen_peer)
				seen_peer = true;
			else
				goto done;
			break;
		case HighlightField:
			on_allowedips = span->len == 10 && !strncasecmp(&msg[span->start], "allowedips", 10);
			break;
		case HighlightIP:
			if (!on_allowedips || !seen_peer)
				break;
			if ((span + 1)->type != HighlightDelimiter || (span + 2)->type != HighlightCidr)
				break;
			if ((span + 2)->len != 1)
				break;
			if (msg[(span + 2)->start] == '0') {
				if (span->len == 7 && !strncmp(&msg[span->start], "0.0.0.0", 7))
					seen_v4_00 = true;
				else if (span->len == 2 && !strncmp(&msg[span->start], "::", 2))
					seen_v6_00 = true;
			} else if (msg[(span + 2)->start] == '1') {
				if (span->len == 7 && !strncmp(&msg[span->start], "0.0.0.0", 7))
					seen_v4_01 = true;
				else if (span->len == 9 && !strncmp(&msg[span->start], "128.0.0.0", 9))
					seen_v4_1281 = true;
				else if (span->len == 2 && !strncmp(&msg[span->start], "::", 2))
					seen_v6_01 = true;
				else if (span->len == 6 && !strncmp(&msg[span->start], "8000::", 6))
					seen_v6_80001 = true;
			}
			break;
		}
	}

	if (seen_v4_00 || seen_v6_00)
		state = BlockingUntunneledTraffic;
	else if ((seen_v4_01 && seen_v4_1281) || (seen_v6_01 && seen_v6_80001))
		state = NotBlockingUntunneledTraffic;

done:
	if (state != this->last_block_state) {
		SendMessage(hWnd, SE_TRAFFIC_BLOCK, 0, state);
		this->last_block_state = state;
	}
}

static void highlight_text(HWND hWnd)
{
	struct syntaxedit_data *this = (struct syntaxedit_data *)GetWindowLongPtr(hWnd, GWLP_USERDATA);
	GETTEXTLENGTHEX gettextlengthex = {
		.flags = GTL_NUMBYTES,
		.codepage = CP_ACP /* Probably CP_UTF8 would be better, but (wine at least) returns utf32 sizes. */
	};
	GETTEXTEX gettextex = {
		.flags = GT_NOHIDDENTEXT,
		.codepage = gettextlengthex.codepage
	};
	CHARFORMAT2 format = {
		.cbSize = sizeof(CHARFORMAT2),
		.dwMask = CFM_COLOR | CFM_CHARSET | CFM_SIZE | CFM_BOLD | CFM_ITALIC | CFM_UNDERLINE,
		.dwEffects = CFE_AUTOCOLOR,
		.yHeight = this->yheight ?: 20 * 10,
		.bCharSet = ANSI_CHARSET
	};
	LRESULT msg_size;
	char *msg = NULL;
	struct highlight_span *spans = NULL;
	CHARRANGE orig_selection;
	POINT original_scroll;
	bool found_private_key = false;
	COLORREF bg_color, bg_inversion;

	if (this->highlight_guard)
		return;
	this->highlight_guard = true;

	msg_size = SendMessage(hWnd, EM_GETTEXTLENGTHEX, (WPARAM)&gettextlengthex, 0);
	if (msg_size == E_INVALIDARG)
		return;
	gettextex.cb = msg_size + 1;

	msg = malloc(msg_size + 1);
	if (!msg)
		goto out;
	if (SendMessage(hWnd, EM_GETTEXTEX, (WPARAM)&gettextex, (LPARAM)msg) <= 0)
		goto out;

	/* By default we get CR not CRLF, so just convert to LF. */
	for (size_t i = 0; i < msg_size; ++i) {
		if (msg[i] == '\r')
			msg[i] = '\n';
	}

	spans = highlight_config(msg);
	if (!spans)
		goto out;

	evaluate_untunneled_blocking(this, hWnd, msg, spans);

	this->idoc->lpVtbl->Undo(this->idoc, tomSuspend, NULL);
	SendMessage(hWnd, EM_SETEVENTMASK, 0, 0);
	SendMessage(hWnd, WM_SETREDRAW, FALSE, 0);
	SendMessage(hWnd, EM_EXGETSEL, 0, (LPARAM)&orig_selection);
	SendMessage(hWnd, EM_GETSCROLLPOS, 0, (LPARAM)&original_scroll);
	SendMessage(hWnd, EM_HIDESELECTION, TRUE, 0);
	SendMessage(hWnd, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&format);
	bg_color = GetSysColor(COLOR_WINDOW);
	bg_inversion = (bg_color & RGB(0xFF, 0xFF, 0xFF)) ^ RGB(0xFF, 0xFF, 0xFF);
	SendMessage(hWnd, EM_SETBKGNDCOLOR, 0, bg_color);
	for (struct highlight_span *span = spans; span->type != HighlightEnd; ++span) {
		CHARRANGE selection = { span->start, span->len + span->start };
		SendMessage(hWnd, EM_EXSETSEL, 0, (LPARAM)&selection);
		format.crTextColor = stylemap[span->type].color ^ bg_inversion;
		format.dwEffects = stylemap[span->type].effects;
		SendMessage(hWnd, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&format);
		if (span->type == HighlightPrivateKey && !found_private_key) {
			/* Rather than allocating a new string, we mangle this one, since (for now) we don't use msg again. */
			msg[span->start + span->len] = '\0';
			SendMessage(hWnd, SE_PRIVATE_KEY, 0, (LPARAM)&msg[span->start]);
			found_private_key = true;
		}
	}
	SendMessage(hWnd, EM_SETSCROLLPOS, 0, (LPARAM)&original_scroll);
	SendMessage(hWnd, EM_EXSETSEL, 0, (LPARAM)&orig_selection);
	SendMessage(hWnd, EM_HIDESELECTION, FALSE, 0);
	SendMessage(hWnd, WM_SETREDRAW, TRUE, 0);
	RedrawWindow(hWnd, NULL, NULL, RDW_ERASE | RDW_FRAME | RDW_INVALIDATE | RDW_ALLCHILDREN);
	SendMessage(hWnd, EM_SETEVENTMASK, 0, ENM_CHANGE);
	this->idoc->lpVtbl->Undo(this->idoc, tomResume, NULL);
	if (!found_private_key)
		SendMessage(hWnd, SE_PRIVATE_KEY, 0, 0);

out:
	free(spans);
	free(msg);
	this->highlight_guard = false;
}

static void context_menu(HWND hWnd, INT x, INT y)
{
	GETTEXTLENGTHEX gettextlengthex = {
		.flags = GTL_DEFAULT,
		.codepage = CP_ACP
	};
	/* This disturbing hack grabs the system edit menu normally used for the EDIT control. */
	HMENU popup, menu = LoadMenuW(GetModuleHandleW(L"comctl32.dll"), MAKEINTRESOURCEW(1));
	CHARRANGE selection = { 0 };
	bool has_selection, can_selectall, can_undo, can_paste;
	UINT cmd;

	if (!menu)
		return;

	SendMessage(hWnd, EM_EXGETSEL, 0, (LPARAM)&selection);
	has_selection = selection.cpMax - selection.cpMin;
	can_selectall = selection.cpMin || (selection.cpMax < SendMessage(hWnd, EM_GETTEXTLENGTHEX, (WPARAM)&gettextlengthex, 0));
	can_undo = SendMessage(hWnd, EM_CANUNDO, 0, 0);
	can_paste = SendMessage(hWnd, EM_CANPASTE, CF_TEXT, 0);

	popup = GetSubMenu(menu, 0);
	EnableMenuItem(popup, WM_UNDO, MF_BYCOMMAND | (can_undo ? MF_ENABLED : MF_GRAYED));
	EnableMenuItem(popup, WM_CUT, MF_BYCOMMAND | (has_selection ? MF_ENABLED : MF_GRAYED));
	EnableMenuItem(popup, WM_COPY, MF_BYCOMMAND | (has_selection ? MF_ENABLED : MF_GRAYED));
	EnableMenuItem(popup, WM_PASTE, MF_BYCOMMAND | (can_paste ? MF_ENABLED : MF_GRAYED));
	EnableMenuItem(popup, WM_CLEAR, MF_BYCOMMAND | (has_selection ? MF_ENABLED : MF_GRAYED));
	EnableMenuItem(popup, EM_SETSEL, MF_BYCOMMAND | (can_selectall ? MF_ENABLED : MF_GRAYED));

	/* Delete items that we don't handle. */
	for (int ctl = GetMenuItemCount(popup) - 1; ctl >= 0; --ctl) {
		MENUITEMINFOW menu_item = {
			.cbSize = sizeof(MENUITEMINFOW),
			.fMask = MIIM_FTYPE | MIIM_ID
		};
		if (!GetMenuItemInfoW(popup, ctl, MF_BYPOSITION, &menu_item))
			continue;
		if (menu_item.fType & MFT_SEPARATOR)
			continue;
		switch (menu_item.wID) {
		case WM_UNDO:
		case WM_CUT:
		case WM_COPY:
		case WM_PASTE:
		case WM_CLEAR:
		case EM_SETSEL:
			continue;
		}
		DeleteMenu(popup, ctl, MF_BYPOSITION);
	}
	/* Delete trailing and adjacent separators. */
	for (int ctl = GetMenuItemCount(popup) - 1, end = true; ctl >= 0; --ctl) {
		MENUITEMINFOW menu_item = {
			.cbSize = sizeof(MENUITEMINFOW),
			.fMask = MIIM_FTYPE
		};
		if (!GetMenuItemInfoW(popup, ctl, MF_BYPOSITION, &menu_item))
			continue;
		if (!(menu_item.fType & MFT_SEPARATOR)) {
			end = false;
			continue;
		}
		if (!end && ctl) {
			if (!GetMenuItemInfoW(popup, ctl - 1, MF_BYPOSITION, &menu_item))
				continue;
			if (!(menu_item.fType & MFT_SEPARATOR))
				continue;
		}
		DeleteMenu(popup, ctl, MF_BYPOSITION);
	}

	if (x == -1 && y == -1) {
		RECT rect;
		GetWindowRect(hWnd, &rect);
		x = (rect.left + rect.right) / 2;
		y = (rect.top + rect.bottom) / 2;
	}

	if (GetFocus() != hWnd)
		SetFocus(hWnd);

	cmd = TrackPopupMenu(popup, TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY, x, y, 0, hWnd, NULL);
	if (cmd)
		SendMessage(hWnd, cmd, 0, cmd == EM_SETSEL ? -1 : 0);

	DestroyMenu(menu);
}

static LRESULT CALLBACK child_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	switch (Msg) {
	case WM_CREATE: {
		struct syntaxedit_data *this = calloc(1, sizeof(*this));
		SetWindowLong(hWnd, GWL_EXSTYLE, GetWindowLong(hWnd, GWL_EXSTYLE) & ~WS_EX_CLIENTEDGE);
		assert(this);
		SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)this);
		SendMessage(hWnd, EM_GETOLEINTERFACE, 0, (LPARAM)&this->irich);
		assert(this->irich);
		this->irich->lpVtbl->QueryInterface(this->irich, &IID_ITextDocument, (void **)&this->idoc);
		assert(this->idoc);
		SendMessage(hWnd, EM_SETEVENTMASK, 0, ENM_CHANGE);
		SendMessage(hWnd, EM_SETTEXTMODE, TM_SINGLECODEPAGE, 0);
		break;
	}
	case WM_DESTROY: {
		struct syntaxedit_data *this = (struct syntaxedit_data *)GetWindowLongPtr(hWnd, GWLP_USERDATA);
		this->idoc->lpVtbl->Release(this->idoc);
		this->irich->lpVtbl->Release(this->irich);
		free(this);
	}
	case WM_SETTEXT: {
		LRESULT ret = parent_proc(hWnd, Msg, wParam, lParam);
		highlight_text(hWnd);
		SendMessage(hWnd, EM_EMPTYUNDOBUFFER, 0, 0);
		return ret;
	}
	case SE_SET_PARENT_DPI: {
		struct syntaxedit_data *this = (struct syntaxedit_data *)GetWindowLongPtr(hWnd, GWLP_USERDATA);
		HDC hdc = GetDC(hWnd);
		if (this->yheight)
			SendMessage(hWnd, EM_SETZOOM, GetDeviceCaps(hdc, LOGPIXELSY), wParam);
		this->yheight = MulDiv(20 * 10, wParam, GetDeviceCaps(hdc, LOGPIXELSY));
		ReleaseDC(hWnd, hdc);
		highlight_text(hWnd);
		return 0;
	}
	case WM_REFLECT + WM_COMMAND:
	case WM_COMMAND:
	case WM_REFLECT + WM_NOTIFY:
	case WM_NOTIFY:
		switch (HIWORD(wParam)) {
		case EN_CHANGE:
			highlight_text(hWnd);
			break;
		}
		break;
	case WM_PASTE:
		SendMessage(hWnd, EM_PASTESPECIAL, CF_TEXT, 0);
		return 0;
	case WM_KEYDOWN: {
		WORD key = LOWORD(wParam);
		if ((key == 'V' && GetKeyState(VK_CONTROL) < 0) ||
		    (key == VK_INSERT && GetKeyState(VK_SHIFT) < 0)) {
			SendMessage(hWnd, EM_PASTESPECIAL, CF_TEXT, 0);
			return 0;
		}
		break;
	}
	case WM_CONTEXTMENU:
		context_menu(hWnd, GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
		return 0;
	case WM_THEMECHANGED:
		highlight_text(hWnd);
		break;
	case WM_GETDLGCODE: {
		MSG *m = (MSG *)lParam;
		LRESULT lres = parent_proc(hWnd, Msg, wParam, lParam);
		lres &= ~DLGC_WANTTAB;
		if (m && m->message == WM_KEYDOWN && m->wParam == VK_TAB && GetKeyState(VK_CONTROL) >= 0)
			lres &= ~DLGC_WANTMESSAGE;
		return lres;
	}
	}
	return parent_proc(hWnd, Msg, wParam, lParam);
}

static long has_loaded = 0;

bool register_syntax_edit(void)
{
	WNDCLASSEXW class = { .cbSize = sizeof(WNDCLASSEXW) };
	WNDPROC pp;
	HANDLE lib;

	if (InterlockedCompareExchange(&has_loaded, 1, 0) != 0)
		return !!parent_proc;

	lib = LoadLibraryExW(L"msftedit.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
	if (!lib)
		return false;

	if (!GetClassInfoExW(NULL, L"RICHEDIT50W", &class))
		goto err;
	pp = class.lpfnWndProc;
	if (!pp)
		goto err;
	class.cbSize = sizeof(WNDCLASSEXW);
	class.hInstance	= GetModuleHandleW(NULL);
	class.lpszClassName = L"WgQuickSyntaxEdit";
	class.lpfnWndProc = child_proc;
	if (!RegisterClassExW(&class))
		goto err;
	parent_proc = pp;
	return true;

err:
	FreeLibrary(lib);
	return false;
}
