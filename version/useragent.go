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
	return fmt.Sprintf("WireGuard/%s (%s; %s)", Number, OsName(), runtime.GOARCH)
}
