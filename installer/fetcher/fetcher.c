// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Jason A. Donenfeld. All Rights Reserved.
 */

#include <windows.h>
#include <delayimp.h>
#include <commctrl.h>
#include <shlwapi.h>
#include <ntsecapi.h>
#include <sddl.h>
#include <winhttp.h>
#include <msi.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <wchar.h>
#include "filelist.h"
#include "crypto.h"
#include "systeminfo.h"
#include "constants.h"

static char msi_filename[MAX_PATH];
static volatile bool msi_filename_is_set;
static volatile size_t g_current, g_total;
static HWND progress;
static HANDLE filehandle = INVALID_HANDLE_VALUE;

static wchar_t *L(const char *a)
{
	static wchar_t w[0x2000];
	if (!MultiByteToWideChar(CP_UTF8, 0, a, -1, w, sizeof(w)))
		abort();
	return w;
}

static bool random_string(char hex[static 65])
{
	uint8_t bytes[32];
	if (!RtlGenRandom(bytes, sizeof(bytes)))
		return false;
	for (int i = 0; i < 32; ++i) {
		hex[i * 2] = 87U + (bytes[i] >> 4) + ((((bytes[i] >> 4) - 10U) >> 8) & ~38U);
		hex[i * 2 + 1] = 87U + (bytes[i] & 0xf) + ((((bytes[i] & 0xf) - 10U) >> 8) & ~38U);
	}
	hex[64] = '\0';
	return true;
}

static void set_status(HWND progress, const char *status)
{
	LONG_PTR current_style = GetWindowLongPtrA(progress, GWL_STYLE);
	char buf[0x1000];
	g_total = 0;
	_snprintf_s(buf, sizeof(buf), _TRUNCATE, "WireGuard: %s...", status);
	SetWindowTextA(progress, buf);
	if (!(current_style & PBS_MARQUEE)) {
		SendMessageA(progress, PBM_SETRANGE32, 0, 100);
		SendMessageA(progress, PBM_SETPOS, 0, 0);
		SetWindowLongPtrA(progress, GWL_STYLE, current_style | PBS_MARQUEE);
		SendMessageA(progress, PBM_SETMARQUEE, TRUE, 0);
	}
}

static void set_progress(HWND progress, size_t current, size_t total)
{
	g_current = current;
	g_total = total;
	PostMessageA(progress, WM_APP, 0, 0);
}

static DWORD __stdcall download_thread(void *param)
{
	DWORD ret = 1, bytes_read, bytes_written;
	HINTERNET session = NULL, connection = NULL, request = NULL;
	uint8_t hash[32], computed_hash[32];
	char download_path[MAX_FILENAME_LEN + sizeof(msi_path)], random_filename[64 + 4 + 1];
	char buf[512 * 1024];
	wchar_t total_bytes_str[22];
	size_t total_bytes, current_bytes;
	const char *arch;
	blake2b_ctx hasher;
	SECURITY_ATTRIBUTES security_attributes = { .nLength = sizeof(SECURITY_ATTRIBUTES) };

	(void)param;

	set_status(progress, "determining paths");
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorA("O:BAD:PAI(A;;FA;;;BA)", SDDL_REVISION_1, &security_attributes.lpSecurityDescriptor, NULL))
		goto out;
	if (!GetWindowsDirectoryA(msi_filename, sizeof(msi_filename)) || !PathAppendA(msi_filename, "Temp"))
		goto out;
	if (!random_string(random_filename))
		goto out;
	memcpy(random_filename + 64, ".msi", 5);
	if (!PathAppendA(msi_filename, random_filename))
		goto out;

	set_status(progress, "determining architecture");
	arch = architecture();
	if (!arch)
		goto out;

	set_status(progress, "connecting to server");
	session = WinHttpOpen(L(useragent()), is_win7() ? WINHTTP_ACCESS_TYPE_DEFAULT_PROXY : WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, NULL, NULL, 0);
	if (!session)
		goto out;
	connection = WinHttpConnect(session, L(server), port, 0);
	if (!connection)
		goto out;

	set_status(progress, "downloading installer list");
	request = WinHttpOpenRequest(connection, L"GET", L(msi_path latest_version_file), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_REFRESH | WINHTTP_FLAG_SECURE);
	if (!request)
		goto out;
	if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
		goto out;
	if (!WinHttpReceiveResponse(request, NULL))
		goto out;
	if (!WinHttpReadData(request, buf, sizeof(buf), &bytes_read))
		goto out;
	WinHttpCloseHandle(request);
	request = NULL;
	if (bytes_read <= 0 || bytes_read >= sizeof(buf))
		goto out;

	set_status(progress, "verifying installer list");
	memcpy(download_path, msi_path, strlen(msi_path));
	if (!extract_newest_file(download_path + strlen(msi_path), hash, buf, bytes_read, arch))
		goto out;

	set_status(progress, "creating temporary file");
	filehandle = CreateFileA(msi_filename, GENERIC_WRITE | DELETE, 0, &security_attributes, CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY, NULL);
	if (filehandle == INVALID_HANDLE_VALUE)
		goto out;
	msi_filename_is_set = true;

	set_status(progress, "downloading installer");
	request = WinHttpOpenRequest(connection, L"GET", L(download_path), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
	if (!request)
		goto out;
	if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
		goto out;
	if (!WinHttpReceiveResponse(request, NULL))
		goto out;
	bytes_read = sizeof(total_bytes_str);
	if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX, total_bytes_str, &bytes_read, WINHTTP_NO_HEADER_INDEX))
		goto out;
	total_bytes = wcstoul(total_bytes_str, NULL, 10);
	if (total_bytes > 100 * 1024 * 1024)
		goto out;
	blake2b_init(&hasher, 32, NULL, 0);
	set_progress(progress, 0, total_bytes);
	for (current_bytes = 0;;) {
		if (!WinHttpReadData(request, buf, 8192, &bytes_read))
			goto out;
		if (!bytes_read)
			break;
		current_bytes += bytes_read;
		if (current_bytes > 100 * 1024 * 1024)
			goto out;
		blake2b_update(&hasher, buf, bytes_read);
		if (!WriteFile(filehandle, buf, bytes_read, &bytes_written, NULL) || bytes_read != bytes_written)
			goto out;
		set_progress(progress, current_bytes, total_bytes);
	}
	blake2b_final(&hasher, computed_hash);
	if (memcmp(hash, computed_hash, sizeof(hash)))
		goto out;

	set_status(progress, "launching installer");
	CloseHandle(filehandle); //TODO: I wish this wasn't required.
	filehandle = INVALID_HANDLE_VALUE;
	ShowWindow(progress, SW_HIDE);
	ret = MsiInstallProductA(msi_filename, NULL);
	ret = ret == ERROR_INSTALL_USEREXIT ? ERROR_SUCCESS : ret;

out:
	if (request)
		WinHttpCloseHandle(request);
	if (connection)
		WinHttpCloseHandle(connection);
	if (session)
		WinHttpCloseHandle(session);
	if (security_attributes.lpSecurityDescriptor)
		LocalFree(security_attributes.lpSecurityDescriptor);

	if (ret) {
		ShowWindow(progress, SW_SHOWDEFAULT);
		if (MessageBoxA(progress, "Something went wrong when downloading the WireGuard installer. Would you like to open your web browser to the MSI download page?", "Download Error", MB_YESNO | MB_ICONWARNING) == IDYES) {
			ShellExecuteA(progress, NULL, "https://" server msi_path, NULL, NULL, SW_SHOWNORMAL);
		}
	}
	exit(ret);
	return ret;
}

static int cleanup(void)
{
	BOOL did_delete_via_handle = FALSE;
	FILE_DISPOSITION_INFO disposition = { TRUE };
	if (filehandle != INVALID_HANDLE_VALUE) {
		did_delete_via_handle = SetFileInformationByHandle(filehandle, FileDispositionInfo, &disposition, sizeof(disposition));
		CloseHandle(filehandle);
		filehandle = INVALID_HANDLE_VALUE;
	}
	if (msi_filename_is_set && !did_delete_via_handle) {
		//TODO: how does DeleteFile deal with reparse points?
		for (int i = 0; i < 200 && !DeleteFileA(msi_filename) && GetLastError() != ERROR_FILE_NOT_FOUND; ++i)
			Sleep(200);
	}
	return 0;
}

static FARPROC WINAPI delayed_load_library_hook(unsigned dliNotify, PDelayLoadInfo pdli)
{
	HMODULE library;
	if (dliNotify != dliNotePreLoadLibrary)
		return NULL;
	library = LoadLibraryExA(pdli->szDll, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
	if (!library)
		abort();
	return (FARPROC)library;
}

PfnDliHook __pfnDliNotifyHook2 = delayed_load_library_hook;

static LRESULT CALLBACK wndproc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
{
	(void)uIdSubclass; (void)dwRefData;

	switch (uMsg) {
	case WM_CLOSE:
	case WM_DESTROY: {
		LRESULT ret = DefSubclassProc(hWnd, uMsg, wParam, lParam);
		exit(0);
		return ret;
	}
	case WM_APP: if (g_total) {
		char buf[0x1000], *start, *paren;
		LONG_PTR current_style;
		int chars = GetWindowTextA(progress, buf, sizeof(buf));
		if (chars) {
			start = buf + chars;
			if (start[-1] == '.' && start[-2] == '.' && start[-3] == '.')
				start -= 3;
			else if ((paren = memchr(buf, '(', chars)) && paren > buf)
				start = paren - 1;
			*start = '\0';
			_snprintf_s(start, sizeof(buf) - (start - buf), _TRUNCATE, " (%.2f%%)", g_current * 100.0f / g_total);
			SetWindowTextA(progress, buf);
		}
		current_style = GetWindowLongPtrA(progress, GWL_STYLE);
		if (current_style & PBS_MARQUEE) {
			SetWindowLongPtrA(progress, GWL_STYLE, current_style & ~PBS_MARQUEE);
			SendMessageA(progress, PBM_SETMARQUEE, FALSE, 0);
		}
		SendMessageA(progress, PBM_SETRANGE32, 0, (LPARAM)g_total);
		SendMessageA(progress, PBM_SETPOS, (WPARAM)g_current, 0);
		break;
	}
	}
	return DefSubclassProc(hWnd, uMsg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR pCmdLine, int nCmdShow)
{
	MSG msg;
	HICON icon;
	HDC dc;
	float scale;

	(void)hPrevInstance; (void)pCmdLine; (void)nCmdShow;

	InitCommonControlsEx(&(INITCOMMONCONTROLSEX){ .dwSize = sizeof(INITCOMMONCONTROLSEX), .dwICC = ICC_PROGRESS_CLASS });

	progress = CreateWindowEx(0, PROGRESS_CLASS, "WireGuard Installer",
				  (WS_OVERLAPPEDWINDOW & ~(WS_BORDER | WS_THICKFRAME | WS_MAXIMIZEBOX)) | PBS_MARQUEE | PBS_SMOOTH,
				  CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
				  NULL, NULL, hInstance, NULL);
	SetWindowSubclass(progress, wndproc, 0, 0);
	dc = GetDC(progress);
	scale = GetDeviceCaps(dc, LOGPIXELSY) / 96.0f;
	ReleaseDC(progress, dc);
	icon = LoadIconA(hInstance, MAKEINTRESOURCE(7));
	SendMessageA(progress, WM_SETICON, ICON_BIG, (LPARAM)icon);
	SendMessageA(progress, WM_SETICON, ICON_SMALL, (LPARAM)icon);
	SendMessageA(progress, PBM_SETMARQUEE, TRUE, 0);
	SetWindowPos(progress, HWND_TOPMOST, -1, -1, 500 * scale, 80 * scale, SWP_NOMOVE | SWP_SHOWWINDOW);

	_onexit(cleanup);
	CreateThread(NULL, 0, download_thread, NULL, 0, NULL);

	while (GetMessage(&msg, NULL, 0, 0)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return 0;
}
