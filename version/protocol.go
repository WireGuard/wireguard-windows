/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package version

import (
	"runtime/debug"
	"strings"
)

func ProtoImplementation() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path == "golang.zx2c4.com/wireguard" {
			parts := strings.Split(dep.Version, "-")
			if len(parts) == 3 && len(parts[2]) == 12 {
				return parts[2][:7]
			}
			return dep.Version
		}
	}
	return "unknown"
}
