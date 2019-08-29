/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package version

import (
	"fmt"
	"runtime"
)

func UserAgent() string {
	name, ver := RunningNameVersion()
	return fmt.Sprintf("%s/%s (%s; %s)", name, ver, OsName(), runtime.GOARCH)
}
