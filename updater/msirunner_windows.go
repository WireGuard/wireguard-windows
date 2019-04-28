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
	// BUG: The Go documentation says that its built-in shell quoting isn't good for msiexec.exe.
	// See https://github.com/golang/go/issues/15566. But perhaps our limited set of options
	// actually works fine? Investigate this!
	return exec.Command(path.Join(system32, "msiexec.exe"), "/quiet", "/i", msiPath).Run()
}

func msiSaveDirectory() (string, error) {
	configRootDir, err := conf.RootDirectory()
	if err != nil {
		return "", err
	}
	return path.Join(configRootDir, "Updates"), nil
}
