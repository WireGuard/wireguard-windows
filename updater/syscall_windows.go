/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2020 WireGuard LLC. All Rights Reserved.
 */

package updater

import "golang.org/x/sys/windows"

//sys	isWow64Process2Internal(process windows.Handle, processMachine *uint16, nativeMachine *uint16) (err error) = kernel32.IsWow64Process2

func isWow64Process2(process windows.Handle) (processMachine, nativeMachine uint16, err error) {
	err = procIsWow64Process2.Find()
	if err != nil {
		return
	}
	err = isWow64Process2Internal(process, &processMachine, &nativeMachine)
	return
}
