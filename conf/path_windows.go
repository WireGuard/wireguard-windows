/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

var cachedConfigFileDir string
var cachedRootDir string

func tunnelConfigurationsDirectory() (string, error) {
	if cachedConfigFileDir != "" {
		return cachedConfigFileDir, nil
	}
	root, err := RootDirectory()
	if err != nil {
		return "", err
	}
	c := filepath.Join(root, "Configurations")
	maybeMigrate(c)
	err = os.MkdirAll(c, os.ModeDir|0700)
	if err != nil {
		return "", err
	}
	cachedConfigFileDir = c
	return cachedConfigFileDir, nil
}

func RootDirectory() (string, error) {
	if cachedRootDir != "" {
		return cachedRootDir, nil
	}
	root, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_CREATE)
	if err != nil {
		return "", err
	}
	c := filepath.Join(root, "WireGuard")
	err = os.MkdirAll(c, os.ModeDir|0700)
	if err != nil {
		return "", err
	}
	cachedRootDir = c
	return cachedRootDir, nil
}
