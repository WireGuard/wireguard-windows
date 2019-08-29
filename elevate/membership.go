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
	err = windows.DuplicateTokenEx(token, windows.TOKEN_QUERY | windows.TOKEN_IMPERSONATE, nil, windows.SecurityIdentification, windows.TokenImpersonation, &checkableToken)
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
