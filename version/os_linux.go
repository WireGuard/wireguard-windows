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

// This isn't a Linux program, yes, but having the updater package work across platforms is quite helpful for testing.

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
