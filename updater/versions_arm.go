/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2020 WireGuard LLC. All Rights Reserved.
 */

package updater

import (
	"debug/pe"
	"errors"

	"golang.org/x/sys/windows"
)

func findArch() (string, error) {
	var processMachine, nativeMachine uint16
	err := windows.IsWow64Process2(windows.CurrentProcess(), &processMachine, &nativeMachine)
	if err != nil {
		return "", err
	}
	switch nativeMachine {
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64", nil
	case pe.IMAGE_FILE_MACHINE_ARMNT:
		return "arm", nil
	}
	return "", errors.New("Invalid GOARCH")
}
