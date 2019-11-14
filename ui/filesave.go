/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"os"

	"github.com/lxn/walk"

	"golang.zx2c4.com/wireguard/windows/l18n"
)

func writeFileWithOverwriteHandling(owner walk.Form, filePath string, write func(file *os.File) error) bool {
	showError := func(err error) bool {
		if err == nil {
			return false
		}

		showErrorCustom(owner, l18n.Sprintf("Writing file failed"), err.Error())

		return true
	}

	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		if os.IsExist(err) {
			if walk.DlgCmdNo == walk.MsgBox(owner, l18n.Sprintf("Writing file failed"), l18n.Sprintf(`File ‘%s’ already exists.

Do you want to overwrite it?`, filePath), walk.MsgBoxYesNo|walk.MsgBoxDefButton2|walk.MsgBoxIconWarning) {
				return false
			}

			if file, err = os.Create(filePath); err != nil {
				return !showError(err)
			}
		} else {
			return !showError(err)
		}
	}
	defer file.Close()

	return !showError(write(file))
}
