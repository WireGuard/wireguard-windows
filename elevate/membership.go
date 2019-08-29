/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package elevate

import (
	"golang.org/x/sys/windows"
)

func isAdmin(token windows.Token) bool {
	builtinAdminsGroup, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}
	var checkableToken windows.Token
	err = windows.DuplicateTokenEx(token, windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE, nil, windows.SecurityIdentification, windows.TokenImpersonation, &checkableToken)
	if err != nil {
		return false
	}
	defer checkableToken.Close()
	isAdmin, err := checkableToken.IsMember(builtinAdminsGroup)
	return isAdmin && err == nil
}

func TokenIsElevatedOrElevatable(token windows.Token) bool {
	if token.IsElevated() && isAdmin(token) {
		return true
	}
	linked, err := token.GetLinkedToken()
	if err != nil {
		return false
	}
	defer linked.Close()
	return linked.IsElevated() && isAdmin(linked)
}

func IsAdminDesktop() (bool, error) {
	hwnd := getShellWindow()
	if hwnd == 0 {
		return false, windows.ERROR_INVALID_WINDOW_HANDLE
	}
	var pid uint32
	_, err := getWindowThreadProcessId(hwnd, &pid)
	if err != nil {
		return false, err
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(process)
	var token windows.Token
	err = windows.OpenProcessToken(process, windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE, &token)
	if err != nil {
		return false, err
	}
	defer token.Close()
	return TokenIsElevatedOrElevatable(token), nil
}

func AdminGroupName() string {
	builtinAdminsGroup, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return "Administrators"
	}
	name, _, _, err := builtinAdminsGroup.LookupAccount("")
	if err != nil {
		return "Administrators"
	}
	return name
}
