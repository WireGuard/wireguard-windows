/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package version

import (
	"fmt"
	"runtime"
)

func Arch() string {
	switch runtime.GOARCH {
	case "arm", "arm64", "amd64":
		return runtime.GOARCH
	case "386":
		return "x86"
	default:
		panic("Unrecognized GOARCH")
	}
}

func UserAgent() string {
	return fmt.Sprintf("WireGuard/%s (%s; %s)", Number, OsName(), Arch())
}
