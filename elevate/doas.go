/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package elevate

import (
	"errors"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func DoAsSystem(f func() error) error {
	runtime.LockOSThread()
	defer func() {
		windows.RevertToSelf()
		runtime.UnlockOSThread()
	}()
	privileges := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{
				Attributes: windows.SE_PRIVILEGE_ENABLED,
			},
		},
	}
	err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeDebugPrivilege"), &privileges.Privileges[0].Luid)
	if err != nil {
		return err
	}
	err = windows.ImpersonateSelf(windows.SecurityImpersonation)
	if err != nil {
		return err
	}
	var threadToken windows.Token
	err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY|windows.TOKEN_ADJUST_PRIVILEGES, false, &threadToken)
	if err != nil {
		return err
	}
	defer threadToken.Close()
	tokenUser, err := threadToken.GetTokenUser()
	if err == nil && tokenUser.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return f()
	}
	err = windows.AdjustTokenPrivileges(threadToken, false, &privileges, uint32(unsafe.Sizeof(privileges)), nil, nil)
	if err != nil {
		return err
	}

	processes, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(processes)

	var winlogonToken windows.Token
	processEntry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for err = windows.Process32First(processes, &processEntry); err == nil; err = windows.Process32Next(processes, &processEntry) {
		if strings.ToLower(windows.UTF16ToString(processEntry.ExeFile[:])) != "winlogon.exe" {
			continue
		}
		winlogonProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, processEntry.ProcessID)
		if err != nil {
			continue
		}
		err = windows.OpenProcessToken(winlogonProcess, windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE|windows.TOKEN_DUPLICATE, &winlogonToken)
		if err != nil {
			windows.CloseHandle(winlogonProcess)
			continue
		}
		tokenUser, err := winlogonToken.GetTokenUser()
		if err != nil || !tokenUser.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
			windows.CloseHandle(winlogonProcess)
			winlogonToken.Close()
			winlogonToken = 0
			continue
		}
		defer windows.CloseHandle(winlogonProcess)
		defer winlogonToken.Close()
		break
	}
	if winlogonToken == 0 {
		return errors.New("unable to find winlogon.exe process")
	}
	var duplicatedToken windows.Token
	err = windows.DuplicateTokenEx(winlogonToken, 0, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &duplicatedToken)
	if err != nil {
		return err
	}
	defer duplicatedToken.Close()
	err = windows.SetThreadToken(nil, duplicatedToken)
	if err != nil {
		return err
	}
	return f()
}
