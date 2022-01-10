/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package elevate

import (
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func DropAllPrivileges(retainDriverLoading bool) error {
	var luid windows.LUID
	if retainDriverLoading {
		err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeLoadDriverPrivilege"), &luid)
		if err != nil {
			return err
		}
	}
	var processToken windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_READ|windows.TOKEN_WRITE, &processToken)
	if err != nil {
		return err
	}
	defer processToken.Close()

	var bufferSizeRequired uint32
	windows.GetTokenInformation(processToken, windows.TokenPrivileges, nil, 0, &bufferSizeRequired)
	if bufferSizeRequired == 0 || bufferSizeRequired < uint32(unsafe.Sizeof(windows.Tokenprivileges{}.PrivilegeCount)) {
		return errors.New("GetTokenInformation failed to provide a buffer size")
	}
	buffer := make([]byte, bufferSizeRequired)
	var bytesWritten uint32
	err = windows.GetTokenInformation(processToken, windows.TokenPrivileges, &buffer[0], uint32(len(buffer)), &bytesWritten)
	if err != nil {
		return err
	}
	if bytesWritten != bufferSizeRequired {
		return errors.New("GetTokenInformation returned incomplete data")
	}
	tokenPrivileges := (*windows.Tokenprivileges)(unsafe.Pointer(&buffer[0]))
	for i := uint32(0); i < tokenPrivileges.PrivilegeCount; i++ {
		item := (*windows.LUIDAndAttributes)(unsafe.Add(unsafe.Pointer(&tokenPrivileges.Privileges[0]), unsafe.Sizeof(tokenPrivileges.Privileges[0])*uintptr(i)))
		if retainDriverLoading && item.Luid == luid {
			continue
		}
		item.Attributes = windows.SE_PRIVILEGE_REMOVED
	}
	err = windows.AdjustTokenPrivileges(processToken, false, tokenPrivileges, 0, nil, nil)
	runtime.KeepAlive(buffer)
	return err
}
