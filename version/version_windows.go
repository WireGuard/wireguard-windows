/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package version

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

//sys	GetFileVersionInfoSize(filename *uint16, zero *uint32) (size uint32, err error) = version.GetFileVersionInfoSizeW
//sys	GetFileVersionInfo(filename *uint16, zero uint32, size uint32, block *byte) (err error) = version.GetFileVersionInfoW
//sys	VerQueryValue(block *byte, section *uint16, value **byte, size *uint32) (err error) = version.VerQueryValueW

type vsFixedFileInfo struct {
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

const vsFixedFileInfoSignature = 0xFEEF04BD

var cachedVersion string

func RunningVersion() string {
	if len(cachedVersion) != 0 {
		return cachedVersion
	}
	key16 := []uint16{'\\', 0x00}
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
	var fixedFileInfo *vsFixedFileInfo
	err = VerQueryValue(&buffer[0], &key16[0], (**byte)(unsafe.Pointer(&fixedFileInfo)), &size)
	if err != nil {
		panic(err)
	}
	if uintptr(size) < unsafe.Sizeof(vsFixedFileInfo{}) || fixedFileInfo == nil || fixedFileInfo.Signature != vsFixedFileInfoSignature {
		panic(errors.New("Incorrect return of VS_FIXEDFILEINFO"))
	}
	version := fmt.Sprintf("%d.%d.%d.%d", (fixedFileInfo.FileVersionMS>>16)&0xffff, (fixedFileInfo.FileVersionMS>>0)&0xffff, (fixedFileInfo.FileVersionLS>>16)&0xffff, (fixedFileInfo.FileVersionLS>>0)&0xffff)
	runtime.KeepAlive(buffer) // The win32 API aliases it in fixedFileInfo, but Go doesn't know that.
	if strings.HasSuffix(version, ".0") {
		version = version[:len(version)-2]
	}
	if strings.HasSuffix(version, ".0") {
		version = version[:len(version)-2]
	}
	cachedVersion = version
	return version
}
