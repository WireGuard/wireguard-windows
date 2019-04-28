/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package version

// #include "../version.h"
import "C"
import (
	"fmt"
	"golang.zx2c4.com/wireguard/device"
	"runtime"
)

const WireGuardWindowsVersion = C.WIREGUARD_WINDOWS_VERSION

func UserAgent() string {
	return fmt.Sprintf("WireGuard/%s (wireguard-go %s; %s; %s; %s)", WireGuardWindowsVersion, device.WireGuardGoVersion, OsName(), runtime.Version(), runtime.GOARCH)
}
