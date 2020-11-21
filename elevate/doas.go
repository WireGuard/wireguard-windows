/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2020 WireGuard LLC. All Rights Reserved.
 */

package elevate

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

func setAllEnv(env []string) {
	windows.Clearenv()
	for _, e := range env {
		kv := strings.SplitN(e, "=", 2)
		if len(kv) != 2 {
			continue
		}
		windows.Setenv(kv[0], kv[1])
	}
}

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
	tokenUser, err := threadToken.GetTokenUser()
	if err == nil && tokenUser.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		threadToken.Close()
		return f()
	}
	err = windows.AdjustTokenPrivileges(threadToken, false, &privileges, uint32(unsafe.Sizeof(privileges)), nil, nil)
	threadToken.Close()
	if err != nil {
		return err
	}

	processes, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return err
	}
	processEntry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	var impersonationError error
	for err = windows.Process32First(processes, &processEntry); err == nil; err = windows.Process32Next(processes, &processEntry) {
		if strings.ToLower(windows.UTF16ToString(processEntry.ExeFile[:])) != "winlogon.exe" {
			continue
		}
		winlogonProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, processEntry.ProcessID)
		if err != nil {
			impersonationError = err
			continue
		}
		var winlogonToken windows.Token
		err = windows.OpenProcessToken(winlogonProcess, windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE|windows.TOKEN_DUPLICATE, &winlogonToken)
		windows.CloseHandle(winlogonProcess)
		if err != nil {
			continue
		}
		tokenUser, err := winlogonToken.GetTokenUser()
		if err != nil || !tokenUser.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
			winlogonToken.Close()
			continue
		}
		windows.CloseHandle(processes)

		var duplicatedToken windows.Token
		err = windows.DuplicateTokenEx(winlogonToken, 0, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &duplicatedToken)
		windows.CloseHandle(winlogonProcess)
		if err != nil {
			return err
		}
		newEnv, err := duplicatedToken.Environ(false)
		if err != nil {
			duplicatedToken.Close()
			return err
		}
		currentEnv := os.Environ()
		err = windows.SetThreadToken(nil, duplicatedToken)
		duplicatedToken.Close()
		if err != nil {
			return err
		}
		setAllEnv(newEnv)
		err = f()
		setAllEnv(currentEnv)
		return err
	}
	windows.CloseHandle(processes)
	if impersonationError != nil {
		return impersonationError
	}
	return errors.New("unable to find winlogon.exe process")
}

func DoAsService(serviceName string, f func() error) error {
	scm, err := mgr.Connect()
	if err != nil {
		return err
	}
	service, err := scm.OpenService(serviceName)
	scm.Disconnect()
	if err != nil {
		return err
	}
	status, err := service.Query()
	service.Close()
	if err != nil {
		return err
	}
	if status.ProcessId == 0 {
		return errors.New("service is not running")
	}
	return DoAsSystem(func() error {
		serviceProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, status.ProcessId)
		if err != nil {
			return err
		}
		var serviceToken windows.Token
		err = windows.OpenProcessToken(serviceProcess, windows.TOKEN_IMPERSONATE|windows.TOKEN_DUPLICATE, &serviceToken)
		windows.CloseHandle(serviceProcess)
		if err != nil {
			return err
		}
		var duplicatedToken windows.Token
		err = windows.DuplicateTokenEx(serviceToken, 0, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &duplicatedToken)
		serviceToken.Close()
		if err != nil {
			return err
		}
		newEnv, err := duplicatedToken.Environ(false)
		if err != nil {
			duplicatedToken.Close()
			return err
		}
		currentEnv := os.Environ()
		err = windows.SetThreadToken(nil, duplicatedToken)
		duplicatedToken.Close()
		if err != nil {
			return err
		}
		setAllEnv(newEnv)
		err = f()
		setAllEnv(currentEnv)
		return err
	})
}
