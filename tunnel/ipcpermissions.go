/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/ipc"

	"golang.zx2c4.com/wireguard/windows/conf"
)

func CopyConfigOwnerToIPCSecurityDescriptor(filename string) error {
	if conf.PathIsEncrypted(filename) {
		return nil
	}
	handle, err := windows.CreateFile(windows.StringToUTF16Ptr(filename), windows.STANDARD_RIGHTS_READ, windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	var sid *windows.SID
	var sd windows.Handle
	//TODO: Move into x/sys/windows
	const SE_FILE_OBJECT = 1
	const OWNER_SECURITY_INFORMATION = 1
	r, _, _ := windows.NewLazySystemDLL("advapi32.dll").NewProc("GetSecurityInfo").Call(
		uintptr(handle),
		SE_FILE_OBJECT,
		OWNER_SECURITY_INFORMATION,
		uintptr(unsafe.Pointer(&sid)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&sd)),
	)
	if r != uintptr(windows.ERROR_SUCCESS) {
		return windows.Errno(r)
	}
	defer windows.LocalFree(sd)
	if sid.IsWellKnown(windows.WinLocalSystemSid) {
		return nil
	}
	sidString, err := sid.String()
	if err != nil {
		return err
	}
	ipc.UAPISecurityDescriptor += fmt.Sprintf("(A;;GA;;;%s)", sidString)
	return nil
}
