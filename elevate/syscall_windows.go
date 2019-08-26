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

type cLIST_ENTRY struct {
	Flink *cLIST_ENTRY
	Blink *cLIST_ENTRY
}

/* The below three structs have several "reserved" members. These are of course well-known and extensively reverse-
 * engineered, but the below shows only the documented and therefore stable fields from Microsoft's winternl.h header */

type cLDR_DATA_TABLE_ENTRY struct {
	Reserved1          [2]uintptr
	InMemoryOrderLinks cLIST_ENTRY
	Reserved2          [2]uintptr
	DllBase            uintptr
	Reserved3          [2]uintptr
	FullDllName        cUNICODE_STRING
	Reserved4          [8]byte
	Reserved5          [3]uintptr
	Reserved6          uintptr
	TimeDateStamp      uint32
}

type cPEB_LDR_DATA struct {
	Reserved1               [8]byte
	Reserved2               [3]uintptr
	InMemoryOrderModuleList cLIST_ENTRY
}

type cPEB struct {
	Reserved1              [2]byte
	BeingDebugged          byte
	Reserved2              [1]byte
	Reserved3              uintptr
	ImageBaseAddress       uintptr
	Ldr                    *cPEB_LDR_DATA
	ProcessParameters      uintptr
	Reserved4              [3]uintptr
	AtlThunkSListPtr       uintptr
	Reserved5              uintptr
	Reserved6              uint32
	Reserved7              uintptr
	Reserved8              uint32
	AtlThunkSListPtr32     uint32
	Reserved9              [45]uintptr
	Reserved10             [96]byte
	PostProcessInitRoutine uintptr
	Reserved11             [128]byte
	Reserved12             [1]uintptr
	SessionId              uint32
}

const (
	cCLSCTX_LOCAL_SERVER      = 4
	cCOINIT_APARTMENTTHREADED = 2
)

//sys	getSystemWindowsDirectory(windowsDirectory *uint16, inLen uint32) (outLen uint32, err error) [failretval==0] = kernel32.GetSystemWindowsDirectoryW

//sys	rtlInitUnicodeString(destinationString *cUNICODE_STRING, sourceString *uint16) = ntdll.RtlInitUnicodeString
//sys	rtlGetCurrentPeb() (peb *cPEB) = ntdll.RtlGetCurrentPeb

//sys	coInitializeEx(reserved uintptr, coInit uint32) (ret error) = ole32.CoInitializeEx
//sys	coUninitialize() = ole32.CoUninitialize
//sys	coGetObject(name *uint16, bindOpts *cBIND_OPTS3, guid *windows.GUID, functionTable ***[0xffff]uintptr) (ret error) = ole32.CoGetObject
