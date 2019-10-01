/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package elevate

import (
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"golang.zx2c4.com/wireguard/windows/version"
)

const (
	releaseOffset      = 2
	shellExecuteOffset = 9

	cSEE_MASK_DEFAULT = 0
)

func ShellExecute(program string, arguments string, directory string, show int32) (err error) {
	var (
		program16   *uint16
		arguments16 *uint16
		directory16 *uint16
	)

	if len(program) > 0 {
		program16, _ = windows.UTF16PtrFromString(program)
	}
	if len(arguments) > 0 {
		arguments16, _ = windows.UTF16PtrFromString(arguments)
	}
	if len(directory) > 0 {
		directory16, _ = windows.UTF16PtrFromString(directory)
	}

	defer func() {
		if err != nil {
			err = windows.ShellExecute(0, windows.StringToUTF16Ptr("runas"), program16, arguments16, directory16, show)
		}
	}()

	if !version.IsRunningEVSigned() {
		err = windows.ERROR_INSUFFICIENT_LOGON_INFO
		return
	}

	var processToken windows.Token
	err = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &processToken)
	if err != nil {
		return
	}
	defer processToken.Close()
	if processToken.IsElevated() {
		err = windows.ERROR_SUCCESS
		return
	}
	if !TokenIsElevatedOrElevatable(processToken) {
		err = windows.ERROR_ACCESS_DENIED
		return
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", registry.QUERY_VALUE)
	if err != nil {
		return
	}
	promptBehavior, _, err := key.GetIntegerValue("ConsentPromptBehaviorAdmin")
	key.Close()
	if err != nil {
		return
	}
	if uint32(promptBehavior) == 0 {
		err = windows.ERROR_SUCCESS
		return
	}
	if uint32(promptBehavior) != 5 {
		err = windows.ERROR_ACCESS_DENIED
		return
	}

	key, err = registry.OpenKey(registry.LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\UAC\\COMAutoApprovalList", registry.QUERY_VALUE)
	if err == nil {
		var autoApproved uint64
		autoApproved, _, err = key.GetIntegerValue("{3E5FC7F9-9A51-4367-9063-A120244FBEC7}")
		key.Close()
		if err != nil {
			return
		}
		if uint32(autoApproved) == 0 {
			err = windows.ERROR_ACCESS_DENIED
			return
		}
	}
	dataTableEntry, err := findCurrentDataTableEntry()
	if err != nil {
		return
	}
	windowsDirectory, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return
	}
	originalPath := dataTableEntry.FullDllName.Buffer
	explorerPath := windows.StringToUTF16Ptr(filepath.Join(windowsDirectory, "explorer.exe"))
	rtlInitUnicodeString(&dataTableEntry.FullDllName, explorerPath)
	defer func() {
		rtlInitUnicodeString(&dataTableEntry.FullDllName, originalPath)
		runtime.KeepAlive(explorerPath)
	}()

	if err = coInitializeEx(0, cCOINIT_APARTMENTTHREADED); err == nil {
		defer coUninitialize()
	}

	var interfacePointer **[0xffff]uintptr
	if err = coGetObject(
		windows.StringToUTF16Ptr("Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"),
		&cBIND_OPTS3{
			cbStruct:       uint32(unsafe.Sizeof(cBIND_OPTS3{})),
			dwClassContext: cCLSCTX_LOCAL_SERVER,
		},
		&windows.GUID{0x6EDD6D74, 0xC007, 0x4E75, [8]byte{0xB7, 0x6A, 0xE5, 0x74, 0x09, 0x95, 0xE2, 0x4C}},
		&interfacePointer,
	); err != nil {
		return
	}

	defer syscall.Syscall((*interfacePointer)[releaseOffset], 1, uintptr(unsafe.Pointer(interfacePointer)), 0, 0)

	if ret, _, _ := syscall.Syscall6((*interfacePointer)[shellExecuteOffset], 6,
		uintptr(unsafe.Pointer(interfacePointer)),
		uintptr(unsafe.Pointer(program16)),
		uintptr(unsafe.Pointer(arguments16)),
		uintptr(unsafe.Pointer(directory16)),
		cSEE_MASK_DEFAULT,
		uintptr(show),
	); ret != uintptr(windows.ERROR_SUCCESS) {
		err = syscall.Errno(ret)
		return
	}

	err = nil
	return
}
