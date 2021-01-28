/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package version

import (
	"debug/pe"
	"errors"
	"fmt"
	"runtime"

	"golang.org/x/sys/windows"
)

var arch string

func NativeArch() string {
	if len(arch) > 0 {
		return arch
	}
	var processMachine, nativeMachine uint16
	err := windows.IsWow64Process2(windows.CurrentProcess(), &processMachine, &nativeMachine)
	if err != nil && errors.Is(err, windows.ERROR_PROC_NOT_FOUND) {
		var b bool
		err = windows.IsWow64Process(windows.CurrentProcess(), &b)
		if err != nil {
			panic(err)
		}
		if b && runtime.GOARCH == "x86" {
			nativeMachine = pe.IMAGE_FILE_MACHINE_AMD64
		} else if b && runtime.GOARCH == "arm" {
			nativeMachine = pe.IMAGE_FILE_MACHINE_ARM64
		} else {
			switch runtime.GOARCH {
			case "arm":
				nativeMachine = pe.IMAGE_FILE_MACHINE_ARMNT
			case "arm64":
				nativeMachine = pe.IMAGE_FILE_MACHINE_ARM64
			case "amd64":
				nativeMachine = pe.IMAGE_FILE_MACHINE_AMD64
			case "386":
				nativeMachine = pe.IMAGE_FILE_MACHINE_I386
			default:
				panic("Unrecognized GOARCH")
			}
		}
	} else if err != nil {
		panic(err)
	}
	switch nativeMachine {
	case pe.IMAGE_FILE_MACHINE_ARMNT:
		arch = "arm"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		arch = "arm64"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		arch = "amd64"
	case pe.IMAGE_FILE_MACHINE_I386:
		arch = "x86"
	default:
		panic("Unrecognized machine type")
	}
	return arch
}

func UserAgent() string {
	return fmt.Sprintf("WireGuard/%s (%s; %s)", Number, OsName(), NativeArch())
}
