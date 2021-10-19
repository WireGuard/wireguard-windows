/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package driver

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

/* TODO: put this into x/sys/windows */
var verQueryValue = windows.NewLazySystemDLL("version.dll").NewProc("VerQueryValueW")

type VS_FIXEDFILEINFO struct {
	Signature        uint32
	StrucVersion     uint32
	FileVersionMS    uint32
	FileVersionLS    uint32
	ProductVersionMS uint32
	ProductVersionLS uint32
	FileFlagsMask    uint32
	FileFlags        uint32
	FileOS           uint32
	FileType         uint32
	FileSubtype      uint32
	FileDateMS       uint32
	FileDateLS       uint32
}

func Version() string {
	if modwireguard.Load() != nil {
		return "unknown"
	}
	resInfo, err := windows.FindResource(modwireguard.Base, windows.ResourceID(1), windows.RT_VERSION)
	if err != nil {
		return "unknown"
	}
	data, err := windows.LoadResourceData(modwireguard.Base, resInfo)
	if err != nil {
		return "unknown"
	}

	var fixedInfo *VS_FIXEDFILEINFO
	fixedInfoLen := uint32(unsafe.Sizeof(*fixedInfo))
	ret, _, _ := verQueryValue.Call(uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(`\`))), uintptr(unsafe.Pointer(&fixedInfo)), uintptr(unsafe.Pointer(&fixedInfoLen)))
	if ret == 0 {
		return "unknown"
	}
	version := fmt.Sprintf("%d.%d", (fixedInfo.FileVersionMS>>16)&0xff, (fixedInfo.FileVersionMS>>0)&0xff)
	if nextNibble := (fixedInfo.FileVersionLS >> 16) & 0xff; nextNibble != 0 {
		version += fmt.Sprintf(".%d", nextNibble)
	}
	if nextNibble := (fixedInfo.FileVersionLS >> 0) & 0xff; nextNibble != 0 {
		version += fmt.Sprintf(".%d", nextNibble)
	}
	return version
}
