// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2021 Jason A. Donenfeld. All Rights Reserved.
 */

#include "systeminfo.h"
#include "version.h"
#include <windows.h>
#include <stdbool.h>
#include <stdio.h>

extern NTAPI __declspec(dllimport) void RtlGetNtVersionNumbers(DWORD *MajorVersion, DWORD *MinorVersion, DWORD *BuildNumber);

const char *architecture(void)
{
	static const char *cached_arch;
	HMODULE kernel32;
	BOOL(WINAPI *IsWow64Process2)(HANDLE hProcess, USHORT *pProcessMachine, USHORT *pNativeMachine);
	USHORT process_machine, native_machine;
	BOOL is_wow64_process;

	if (cached_arch)
		return cached_arch;

	kernel32 = GetModuleHandleA("kernel32.dll");
	if (!kernel32)
		return NULL;
	*(FARPROC *)&IsWow64Process2 = GetProcAddress(kernel32, "IsWow64Process2");
	if (IsWow64Process2) {
		if (!IsWow64Process2(GetCurrentProcess(), &process_machine, &native_machine))
			return NULL;
		switch (native_machine) {
		case IMAGE_FILE_MACHINE_I386:
			return cached_arch = "x86";
		case IMAGE_FILE_MACHINE_AMD64:
			return cached_arch = "amd64";
		case IMAGE_FILE_MACHINE_ARMNT:
			return cached_arch = "arm";
		case IMAGE_FILE_MACHINE_ARM64:
			return cached_arch = "arm64";
		}
	} else {
		if (!IsWow64Process(GetCurrentProcess(), &is_wow64_process))
			return NULL;
		return cached_arch = is_wow64_process ? "amd64" : "x86";
	}
	return NULL;
}

const char *useragent(void)
{
	static char useragent[0x200];
	DWORD maj, min, build;

	if (useragent[0])
		return useragent;
	RtlGetNtVersionNumbers(&maj, &min, &build);
	_snprintf_s(useragent, sizeof(useragent), _TRUNCATE, "WireGuard-Fetcher/" VERSION_STR " (Windows %lu.%lu.%lu; %s)", maj, min, build & 0xffff, architecture());
	return useragent;
}

bool is_win7(void)
{
	DWORD maj, min, build;
	RtlGetNtVersionNumbers(&maj, &min, &build);
	return maj == 6 && min == 1;
}
