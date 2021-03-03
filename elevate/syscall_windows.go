/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
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

const (
	cCLSCTX_LOCAL_SERVER      = 4
	cCOINIT_APARTMENTTHREADED = 2
)

//sys	coInitializeEx(reserved uintptr, coInit uint32) (ret error) = ole32.CoInitializeEx
//sys	coUninitialize() = ole32.CoUninitialize
//sys	coGetObject(name *uint16, bindOpts *cBIND_OPTS3, guid *windows.GUID, functionTable ***[0xffff]uintptr) (ret error) = ole32.CoGetObject
