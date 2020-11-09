// +build !arm

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2020 WireGuard LLC. All Rights Reserved.
 */

package updater

import (
	"errors"
	"runtime"
)

func findArch() (arch string, err error) {
	if runtime.GOARCH == "amd64" {
		arch = "amd64"
	} else if runtime.GOARCH == "386" {
		arch = "x86"
	} else if runtime.GOARCH == "arm" {
		arch = "arm"
	} else if runtime.GOARCH == "arm64" {
		arch = "arm64"
	} else {
		err = errors.New("Invalid GOARCH")
	}
	return
}
