/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/ipc/winpipe"
)

//sys	coTaskMemFree(pointer uintptr) = ole32.CoTaskMemFree
//sys	shGetKnownFolderPath(id *windows.GUID, flags uint32, token windows.Handle, path **uint16) (err error) [failretval!=0] = shell32.SHGetKnownFolderPath
var folderIDLocalAppData = windows.GUID{0xf1b32785, 0x6fba, 0x4fcf, [8]byte{0x9d, 0x55, 0x7b, 0x8e, 0x7f, 0x15, 0x70, 0x91}}
var folderIDProgramData = windows.GUID{0x62ab5d82, 0xfdc1, 0x4dc3, [8]byte{0xa9, 0xdd, 0x07, 0x0d, 0x1d, 0x49, 0x5d, 0x97}}

const kfFlagCreate = 0x00008000

var cachedConfigFileDir string
var cachedRootDir string

func tunnelConfigurationsDirectory() (string, error) {
	if cachedConfigFileDir != "" {
		return cachedConfigFileDir, nil
	}
	root, err := RootDirectory()
	if err != nil {
		return "", err
	}
	c := filepath.Join(root, "Configurations")
	err = os.MkdirAll(c, os.ModeDir|0700)
	if err != nil {
		return "", err
	}
	cachedConfigFileDir = c
	return cachedConfigFileDir, nil
}

func maybeMigrate(dst string) {
	var path *uint16
	err := shGetKnownFolderPath(&folderIDLocalAppData, kfFlagCreate, 0, &path)
	if err != nil {
		return
	}
	root := windows.UTF16ToString((*[(1<<31)-1]uint16)(unsafe.Pointer(path))[:])
	coTaskMemFree(uintptr(unsafe.Pointer(path)))
	if len(root) == 0 {
		return
	}
	c := windows.StringToUTF16Ptr(filepath.Join(root, "WireGuard", "Configurations"))
	attr, err := windows.GetFileAttributes(c)
	if err != nil || attr & windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return
	}
	dst16 := windows.StringToUTF16Ptr(filepath.Join(dst, "Configurations"))

	err = windows.MoveFileEx(c, dst16, windows.MOVEFILE_COPY_ALLOWED | windows.MOVEFILE_REPLACE_EXISTING)
	if err == nil {
		os.RemoveAll(filepath.Join(root, "WireGuard"))
	}
}

func RootDirectory() (string, error) {
	if cachedRootDir != "" {
		return cachedRootDir, nil
	}

	sd, err := winpipe.SddlToSecurityDescriptor("O:SYD:(A;;GA;;;SY)")
	if err != nil {
		return "", err
	}
	sa := &windows.SecurityAttributes{
		Length:             uint32(len(sd)),
		SecurityDescriptor: uintptr(unsafe.Pointer(&sd[0])),
	}

	var path *uint16
	err = shGetKnownFolderPath(&folderIDProgramData, kfFlagCreate, 0, &path)
	if err != nil {
		return "", err
	}
	defer coTaskMemFree(uintptr(unsafe.Pointer(path)))
	root := windows.UTF16ToString((*[windows.MAX_LONG_PATH + 1]uint16)(unsafe.Pointer(path))[:])
	if len(root) == 0 {
		return "", errors.New("Unable to determine configuration directory")
	}
	c := filepath.Join(root, "WireGuard")

	err = windows.CreateDirectory(windows.StringToUTF16Ptr(c), sa)
	if err == nil {
		maybeMigrate(c)
	} else if err != windows.ERROR_ALREADY_EXISTS {
		return "", err
	}

	cachedRootDir = c
	return cachedRootDir, nil
}
