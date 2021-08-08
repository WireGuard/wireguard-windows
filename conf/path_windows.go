/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var cachedConfigFileDir string
var cachedRootDir string

func tunnelConfigurationsDirectory() (string, error) {
	if cachedConfigFileDir != "" {
		return cachedConfigFileDir, nil
	}
	root, err := RootDirectory(true)
	if err != nil {
		return "", err
	}
	c := filepath.Join(root, "Configurations")
	err = os.Mkdir(c, os.ModeDir|0700)
	if err != nil && !os.IsExist(err) {
		return "", err
	}
	cachedConfigFileDir = c
	return cachedConfigFileDir, nil
}

// PresetRootDirectory causes RootDirectory() to not try any automatic deduction, and instead
// uses what's passed to it. This isn't used by wireguard-windows, but is useful for external
// consumers of our libraries who might want to do strange things.
func PresetRootDirectory(root string) {
	cachedRootDir = root
}

func RootDirectory(create bool) (string, error) {
	if cachedRootDir != "" {
		return cachedRootDir, nil
	}
	root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return "", err
	}
	root = filepath.Join(root, "WireGuard")
	if !create {
		return filepath.Join(root, "Data"), nil
	}
	root16, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return "", err
	}

	// The root directory inherits its ACL from Program Files; we don't want to mess with that
	err = windows.CreateDirectory(root16, nil)
	if err != nil && err != windows.ERROR_ALREADY_EXISTS {
		return "", err
	}

	dataDirectorySd, err := windows.SecurityDescriptorFromString("O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return "", err
	}
	dataDirectorySa := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: dataDirectorySd,
	}

	data := filepath.Join(root, "Data")
	data16, err := windows.UTF16PtrFromString(data)
	if err != nil {
		return "", err
	}
	var dataHandle windows.Handle
	for {
		err = windows.CreateDirectory(data16, dataDirectorySa)
		if err != nil && err != windows.ERROR_ALREADY_EXISTS {
			return "", err
		}
		dataHandle, err = windows.CreateFile(data16, windows.READ_CONTROL|windows.WRITE_OWNER|windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY, 0)
		if err != nil && err != windows.ERROR_FILE_NOT_FOUND {
			return "", err
		}
		if err == nil {
			break
		}
	}
	defer windows.CloseHandle(dataHandle)
	var fileInfo windows.ByHandleFileInformation
	err = windows.GetFileInformationByHandle(dataHandle, &fileInfo)
	if err != nil {
		return "", err
	}
	if fileInfo.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return "", errors.New("Data directory is actually a file")
	}
	if fileInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return "", errors.New("Data directory is reparse point")
	}
	buf := make([]uint16, windows.MAX_PATH+4)
	for {
		bufLen, err := windows.GetFinalPathNameByHandle(dataHandle, &buf[0], uint32(len(buf)), 0)
		if err != nil {
			return "", err
		}
		if bufLen < uint32(len(buf)) {
			break
		}
		buf = make([]uint16, bufLen)
	}
	if !strings.EqualFold(`\\?\`+data, windows.UTF16ToString(buf[:])) {
		return "", errors.New("Data directory jumped to unexpected location")
	}
	err = windows.SetKernelObjectSecurity(dataHandle, windows.DACL_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, dataDirectorySd)
	if err != nil {
		return "", err
	}
	cachedRootDir = data
	return cachedRootDir, nil
}

func LogFile(createRoot bool) (string, error) {
	root, err := RootDirectory(createRoot)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "log.bin"), nil
}