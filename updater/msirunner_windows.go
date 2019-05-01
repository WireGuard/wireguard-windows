/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package updater

import (
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/conf"
	"os/exec"
	"path"
)

func runMsi(msiPath string) error {
	system32, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	cmd := exec.Command(path.Join(system32, "msiexec.exe"), "/qb-", "/i", path.Base(msiPath))
	cmd.Dir = path.Dir(msiPath)
	return cmd.Run()
}

func msiSaveDirectory() (string, error) {
	configRootDir, err := conf.RootDirectory()
	if err != nil {
		return "", err
	}
	return path.Join(configRootDir, "Updates"), nil
}
