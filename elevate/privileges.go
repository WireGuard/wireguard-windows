/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
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
		item := (*windows.LUIDAndAttributes)(unsafe.Pointer(uintptr(unsafe.Pointer(&tokenPrivileges.Privileges[0])) + unsafe.Sizeof(tokenPrivileges.Privileges[0])*uintptr(i)))
		if retainDriverLoading && item.Luid == luid {
			continue
		}
		item.Attributes = windows.SE_PRIVILEGE_REMOVED
	}
	err = windows.AdjustTokenPrivileges(processToken, false, tokenPrivileges, 0, nil, nil)
	runtime.KeepAlive(buffer)
	return err
}

func GetDefaultObjectDacl() (owner, group *windows.SID, dacl *windows.ACL, err error) {
	sd, err := windows.SecurityDescriptorFromString("O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FR;;;BA)")
	if err != nil {
		return nil, nil, nil, err
	}
	owner, _, err = sd.Owner()
	if err != nil {
		return nil, nil, nil, err
	}
	group, _, err = sd.Group()
	if err != nil {
		return nil, nil, nil, err
	}
	dacl, _, err = sd.DACL()
	if err != nil {
		return nil, nil, nil, err
	}
	return
}

func SetDefaultObjectDacl() error {
	owner, group, dacl, err := GetDefaultObjectDacl()
	if err != nil {
		return err
	}
	var token windows.Token
	err = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_DEFAULT, &token)
	if err != nil {
		return err
	}
	defer token.Close()
	err = windows.SetTokenInformation(token, windows.TokenOwner, (*byte)(unsafe.Pointer(&owner)), uint32(unsafe.Sizeof(uintptr(0))))
	if err != nil {
		return err
	}
	err = windows.SetTokenInformation(token, windows.TokenPrimaryGroup, (*byte)(unsafe.Pointer(&group)), uint32(unsafe.Sizeof(uintptr(0))))
	if err != nil {
		return err
	}
	err = windows.SetTokenInformation(token, windows.TokenDefaultDacl, (*byte)(unsafe.Pointer(&dacl)), uint32(unsafe.Sizeof(uintptr(0))))
	if err != nil {
		return err
	}
	//TODO: sacl?
	return nil
}