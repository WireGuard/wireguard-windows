/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2020 WireGuard LLC. All Rights Reserved.
 */

package updater

import (
	"errors"

	"golang.org/x/sys/windows"
)

func findArch() (arch string, err error) {
	process := windows.CurrentProcess()
	_, nativeMachine, err2 := isWow64Process2(process)
	if err2 != nil {
		var isWow64 bool
		if windows.IsWow64Process(process, &isWow64) != nil || !isWow64 {
			nativeMachine = IMAGE_FILE_MACHINE_ARMNT
		} else {
			nativeMachine = IMAGE_FILE_MACHINE_ARM64
		}
	}
	switch nativeMachine {
	case IMAGE_FILE_MACHINE_ARM64:
		arch = "arm64"
	case IMAGE_FILE_MACHINE_ARMNT:
		arch = "arm"
	default:
		err = errors.New("Invalid GOARCH")
	}
	return
}
