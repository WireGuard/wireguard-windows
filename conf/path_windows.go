/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"unsafe"
)

//sys coTaskMemFree(pointer uintptr) = ole32.CoTaskMemFree
//sys shGetKnownFolderPath(id *windows.GUID, flags uint32, token windows.Handle, path **uint16) (err error) [failretval!=0] = shell32.SHGetKnownFolderPath
var folderIDLocalAppData = windows.GUID{0xf1b32785, 0x6fba, 0x4fcf, [8]byte{0x9d, 0x55, 0x7b, 0x8e, 0x7f, 0x15, 0x70, 0x91}}

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

func RootDirectoryForToken(token windows.Token) (string, error) {
	var path *uint16
	err := shGetKnownFolderPath(&folderIDLocalAppData, kfFlagCreate, windows.Handle(token), &path)
	if err != nil {
		return "", err
	}
	defer coTaskMemFree(uintptr(unsafe.Pointer(path)))
	localAppData := windows.UTF16ToString((*[windows.MAX_LONG_PATH + 1]uint16)(unsafe.Pointer(path))[:])
	if len(localAppData) == 0 {
		return "", errors.New("unable to determine configuration root directory")
	}
	c := filepath.Join(localAppData, "WireGuard")
	err = os.MkdirAll(c, os.ModeDir|0700)
	if err != nil {
		return "", err
	}
	return c, nil
}

func RootDirectory() (string, error) {
	if cachedRootDir != "" {
		return cachedRootDir, nil
	}
	processToken, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return "", err
	}
	c, err := RootDirectoryForToken(processToken)
	processToken.Close()
	if err != nil {
		return "", err
	}
	cachedRootDir = c
	return cachedRootDir, nil
}
