/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package l18n

import (
	"golang.org/x/sys/windows"
)

func getUserLanguages() ([]string, error) {
	return windows.GetUserPreferredUILanguages(windows.MUI_LANGUAGE_NAME)
}
