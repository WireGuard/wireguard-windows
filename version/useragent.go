/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package version

import (
	"fmt"
	"runtime"

	"golang.zx2c4.com/wireguard/device"
)

func UserAgent() string {
	return fmt.Sprintf("WireGuard/%s (wireguard-go %s; %s; %s; %s)", RunningVersion(), device.WireGuardGoVersion, OsName(), runtime.Version(), runtime.GOARCH)
}
