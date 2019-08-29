/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package version

import (
	"bytes"
	"fmt"

	"golang.org/x/sys/unix"
)

// For testing the updater package from linux. Debug stuff only.

func utsToStr(u [65]byte) string {
	i := bytes.IndexByte(u[:], 0)
	if i < 0 {
		return string(u[:])
	}
	return string(u[:i])
}

func OsName() string {
	var utsname unix.Utsname
	if unix.Uname(&utsname) != nil {
		return "Unix Unknown"
	}
	return fmt.Sprintf("%s %s %s", utsToStr(utsname.Sysname), utsToStr(utsname.Release), utsToStr(utsname.Version))
}

func RunningNameVersion() (string, string) {
	return "WireGuard", "0.0.0.0"
}

func VerifyAuthenticode(path string) bool {
	return true
}
