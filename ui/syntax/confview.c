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
#include <richedit.h>
#include <richole.h>
#include <tom.h>

#include "confview.h"
#include "highlighter.h"

static WNDPROC parent_proc;

static void set_rtf(HWND hWnd, const char *str)
{
	SETTEXTEX settextex = {
		.flags = ST_DEFAULT,
		.codepage = CP_ACP
	};
	CHARRANGE orig_selection;
	POINT original_scroll;

	SendMessage(hWnd, WM_SETREDRAW, FALSE, 0);
	SendMessage(hWnd, EM_EXGETSEL, 0, (LPARAM)&orig_selection);
	SendMessage(hWnd, EM_GETSCROLLPOS, 0, (LPARAM)&original_scroll);
	SendMessage(hWnd, EM_HIDESELECTION, TRUE, 0);
	SendMessage(hWnd, EM_SETTEXTEX, (WPARAM)&settextex, (LPARAM)str);
	SendMessage(hWnd, EM_SETSCROLLPOS, 0, (LPARAM)&original_scroll);
	SendMessage(hWnd, EM_EXSETSEL, 0, (LPARAM)&orig_selection);
	SendMessage(hWnd, EM_HIDESELECTION, FALSE, 0);
	SendMessage(hWnd, WM_SETREDRAW, TRUE, 0);
	HideCaret(hWnd);
	RedrawWindow(hWnd, NULL, NULL, RDW_ERASE | RDW_FRAME | RDW_INVALIDATE | RDW_ALLCHILDREN);
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
	bool has_selection, can_selectall;
	UINT cmd;

	if (!menu)
		return;

	SendMessage(hWnd, EM_EXGETSEL, 0, (LPARAM)&selection);
	has_selection = selection.cpMax - selection.cpMin;
	can_selectall = selection.cpMin || (selection.cpMax < SendMessage(hWnd, EM_GETTEXTLENGTHEX, (WPARAM)&gettextlengthex, 0));

	popup = GetSubMenu(menu, 0);
	EnableMenuItem(popup, WM_COPY, MF_BYCOMMAND | (has_selection ? MF_ENABLED : MF_GRAYED));
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
		case WM_COPY:
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
		x = rect.left + (rect.right - rect.left) / 2;
		y = rect.top + (rect.bottom - rect.top) / 2;
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
	case WM_CREATE:
		HideCaret(hWnd);
		break;
	case WM_LBUTTONDOWN:
	case WM_SETFOCUS: {
		LRESULT ret = parent_proc(hWnd, Msg, wParam, lParam);
		HideCaret(hWnd);
		return ret;
	}
	case WM_SETCURSOR:
		return 0;
	case PV_NEWRTF:
		set_rtf(hWnd, (const char *)wParam);
		return 0;
	case WM_CONTEXTMENU:
		context_menu(hWnd, LOWORD(lParam), HIWORD(lParam));
		return 0;
	}
	return parent_proc(hWnd, Msg, wParam, lParam);
}

bool register_conf_view(void)
{
	WNDCLASSEXW class = { .cbSize = sizeof(WNDCLASSEXW) };
	WNDPROC pp;
	HANDLE lib;

	if (parent_proc)
		return true;

	lib = LoadLibraryW(L"msftedit.dll");
	if (!lib)
		return false;

	if (!GetClassInfoExW(NULL, L"RICHEDIT50W", &class))
		goto err;
	pp = class.lpfnWndProc;
	if (!pp)
		goto err;
	class.cbSize = sizeof(WNDCLASSEXW);
	class.hInstance	= GetModuleHandleW(NULL);
	class.lpszClassName = L"WgConfView";
	class.lpfnWndProc = child_proc;
	if (!RegisterClassExW(&class))
		goto err;
	parent_proc = pp;
	return true;

err:
	FreeLibrary(lib);
	return false;
}
