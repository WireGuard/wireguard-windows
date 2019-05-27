/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package services

import (
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TokenIsMemberOfBuiltInAdministrator(token windows.Token) bool {
	gs, err := token.GetTokenGroups()
	if err != nil {
		return false
	}
	groups := (*[(1 << 28) - 1]windows.SIDAndAttributes)(unsafe.Pointer(&gs.Groups[0]))[:gs.GroupCount]
	isAdmin := false
	for _, g := range groups {
		if (g.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY != 0 || g.Attributes&windows.SE_GROUP_ENABLED != 0) && g.Sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			isAdmin = true
			break
		}
	}
	runtime.KeepAlive(gs)
	return isAdmin
}

func DropAllPrivileges() error {
	processHandle, err := windows.GetCurrentProcess()
	if err != nil {
		return err
	}
	var processToken windows.Token
	err = windows.OpenProcessToken(processHandle, windows.TOKEN_READ|windows.TOKEN_WRITE, &processToken)
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
		(*windows.LUIDAndAttributes)(unsafe.Pointer(uintptr(unsafe.Pointer(&tokenPrivileges.Privileges[0])) + unsafe.Sizeof(tokenPrivileges.Privileges[0])*uintptr(i))).Attributes = windows.SE_PRIVILEGE_REMOVED
	}
	err = windows.AdjustTokenPrivileges(processToken, false, tokenPrivileges, 0, nil, nil)
	runtime.KeepAlive(buffer)
	return err
}
