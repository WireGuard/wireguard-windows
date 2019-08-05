/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package elevate

import (
	"runtime"

	"golang.org/x/sys/windows"
)

func TokenIsMemberOfBuiltInAdministrator(token windows.Token) bool {
	gs, err := token.GetTokenGroups()
	if err != nil {
		return false
	}
	isAdmin := false
	for _, g := range gs.AllGroups() {
		if (g.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY != 0 || g.Attributes&windows.SE_GROUP_ENABLED != 0) && g.Sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			isAdmin = true
			break
		}
	}
	runtime.KeepAlive(gs)
	return isAdmin
}
