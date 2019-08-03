/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package elevate

type cBIND_OPTS3 struct {
	cbStruct            uint32
	grfFlags            uint32
	grfMode             uint32
	dwTickCountDeadline uint32
	dwTrackFlags        uint32
	dwClassContext      uint32
	locale              uint32
	pServerInfo         *uintptr
	hwnd                *uintptr
}

type cUNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type cLDR_DATA_TABLE_ENTRY struct {
	Reserved1          [2]uintptr
	InMemoryOrderLinks [2]uintptr
	Reserved2          [2]uintptr
	DllBase            uintptr
	Reserved3          [2]uintptr
	FullDllName        cUNICODE_STRING
	Reserved4          [8]byte
	Reserved5          [3]uintptr
	Reserved6          uintptr
	TimeDateStamp      uint32
}

const (
	cCLSCTX_LOCAL_SERVER      = 4
	cCOINIT_APARTMENTTHREADED = 2
)

//sys	getModuleHandle(moduleName *uint16) (moduleHandle uintptr, err error) [failretval==0] = kernel32.GetModuleHandleW
//sys	getWindowsDirectory(windowsDirectory *uint16, inLen uint32) (outLen uint32, err error) [failretval==0] = kernel32.GetWindowsDirectoryW

//sys	rtlInitUnicodeString(destinationString *cUNICODE_STRING, sourceString *uint16) = ntdll.RtlInitUnicodeString
//sys	ldrFindEntryForAddress(moduleHandle uintptr, entry **cLDR_DATA_TABLE_ENTRY) (ntstatus uint32) = ntdll.LdrFindEntryForAddress

//sys	coInitializeEx(reserved uintptr, coInit uint32) (ret error) = ole32.CoInitializeEx
//sys	coUninitialize() = ole32.CoUninitialize
//sys	coGetObject(name *uint16, bindOpts *cBIND_OPTS3, guid *windows.GUID, functionTable ***[0xffff]uintptr) (ret error) = ole32.CoGetObject
