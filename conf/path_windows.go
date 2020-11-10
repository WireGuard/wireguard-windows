/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"debug/pe"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var cachedConfigFileDir string
var cachedRootDir string
var disableAutoMigration bool

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
	maybeMigrateConfiguration(c)
	cachedConfigFileDir = c
	return cachedConfigFileDir, nil
}

// PresetRootDirectory causes RootDirectory() to not try any automatic deduction, and instead
// uses what's passed to it. This isn't used by wireguard-windows, but is useful for external
// consumers of our libraries who might want to do strange things.
func PresetRootDirectory(root string) {
	cachedRootDir = root
	disableAutoMigration = true
}

// TODO: replace with x/sys/windows upstreamed function
func setKernelObjectSecurity(handle windows.Handle, securityInformation windows.SECURITY_INFORMATION, securityDescriptor *windows.SECURITY_DESCRIPTOR) (err error) {
	r1, _, e1 := syscall.Syscall(windows.NewLazySystemDLL("advapi32.dll").NewProc("SetKernelObjectSecurity").Addr(), 3, uintptr(handle), uintptr(securityInformation), uintptr(unsafe.Pointer(securityDescriptor)))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}
func getFinalPathNameByHandle(file windows.Handle, filePath *uint16, filePathSize uint32, flags uint32) (n uint32, err error) {
	r0, _, e1 := syscall.Syscall6(windows.NewLazySystemDLL("kernel32.dll").NewProc("GetFinalPathNameByHandleW").Addr(), 4, uintptr(file), uintptr(unsafe.Pointer(filePath)), uintptr(filePathSize), uintptr(flags), 0, 0)
	n = uint32(r0)
	if n == 0 {
		err = errnoErr(e1)
	}
	return
}

func RootDirectory(create bool) (string, error) {
	if cachedRootDir != "" {
		return cachedRootDir, nil
	}
	var isWow bool
	var processMachine, nativeMachine uint16
	err := windows.IsWow64Process2(windows.CurrentProcess(), &processMachine, &nativeMachine)
	if err == nil {
		isWow = processMachine != pe.IMAGE_FILE_MACHINE_UNKNOWN
	} else {
		if !errors.Is(err, windows.ERROR_PROC_NOT_FOUND) {
			return "", err
		}
		err = windows.IsWow64Process(windows.CurrentProcess(), &isWow)
		if err != nil {
			return "", err
		}
	}
	var root string
	if !isWow {
		root, err = windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_CREATE)
		if err != nil {
			return "", err
		}
	} else {
		key, err := registry.OpenKey(windows.HKEY_LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion`, registry.READ|registry.WOW64_64KEY)
		if err != nil {
			return "", err
		}
		var typ uint32
		root, typ, err = key.GetStringValue("ProgramFilesDir")
		key.Close()
		if err != nil {
			return "", err
		}
		if typ != registry.SZ {
			return "", registry.ErrUnexpectedType
		}
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

	dataDirectorySd, err := windows.SecurityDescriptorFromString("O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FR;;;BA)")
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
		dataHandle, err = windows.CreateFile(data16, windows.READ_CONTROL|windows.WRITE_OWNER|windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
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
	var buf [windows.MAX_PATH * 4]uint16
	_, err = getFinalPathNameByHandle(dataHandle, &buf[0], uint32(len(buf)), 0)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(`\\?\`+data, windows.UTF16ToString(buf[:])) {
		return "", fmt.Errorf("Data directory jumped to unexpected location: got %q; want %q", windows.UTF16ToString(buf[:]), `\\?\`+data)
	}
	err = setKernelObjectSecurity(dataHandle, windows.DACL_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, dataDirectorySd)
	if err != nil {
		return "", err
	}
	cachedRootDir = data
	return cachedRootDir, nil
}
