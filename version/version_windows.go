/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package version

import (
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

//sys	GetFileVersionInfoSize(filename *uint16, zero *uint32) (size uint32, err error) = version.GetFileVersionInfoSizeW
//sys	GetFileVersionInfo(filename *uint16, zero uint32, size uint32, block *byte) (err error) = version.GetFileVersionInfoW
//sys	VerQueryValue(block *byte, section *uint16, value **byte, size *uint32) (err error) = version.VerQueryValueW

var cachedVersion, cachedName string

func RunningNameVersion() (name, version string) {
	if len(cachedVersion) != 0 || len(cachedName) != 0 {
		return cachedName, cachedVersion
	}
	self, err := os.Executable()
	if err != nil {
		panic(err)
	}
	self16, err := windows.UTF16PtrFromString(self)
	if err != nil {
		panic(err)
	}
	var zero uint32
	size, err := GetFileVersionInfoSize(self16, &zero)
	if err != nil {
		panic(err)
	}
	buffer := make([]byte, size)
	err = GetFileVersionInfo(self16, zero, size, &buffer[0])
	if err != nil {
		panic(err)
	}

	var val16 *uint16
	err = VerQueryValue(&buffer[0], windows.StringToUTF16Ptr(`\StringFileInfo\040904b0\ProductName`), (**byte)(unsafe.Pointer(&val16)), &size)
	if err != nil {
		panic(err)
	}
	name = windows.UTF16ToString((*[(1 << 30) - 1]uint16)(unsafe.Pointer(val16))[:size])
	err = VerQueryValue(&buffer[0], windows.StringToUTF16Ptr(`\StringFileInfo\040904b0\ProductVersion`), (**byte)(unsafe.Pointer(&val16)), &size)
	if err != nil {
		panic(err)
	}
	version = windows.UTF16ToString((*[(1 << 30) - 1]uint16)(unsafe.Pointer(val16))[:size])
	runtime.KeepAlive(buffer)

	cachedName = name
	cachedVersion = version
	return
}
