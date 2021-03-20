/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"os"
	"path/filepath"
	"strings"
)

var cachedConfigFileDir string
var cachedRootDir string

func tunnelConfigurationsDirectory() (string, error) {
	if cachedConfigFileDir != "" {
		return cachedConfigFileDir, nil
	}
	root, err := RootDirectory(true)
	if err != nil {
		return "", err
	}
	c := filepath.Join(root, "Configurations")
	// Allow access to all
	err = os.Mkdir(c, os.ModeDir|0777)
	if err != nil && !os.IsExist(err) {
		return "", err
	}
	cachedConfigFileDir = c
	return cachedConfigFileDir, nil
}

// PresetRootDirectory causes RootDirectory() to not try any automatic deduction, and instead
// uses what's passed to it. This isn't used by wireguard-windows, but is useful for external
// consumers of our libraries who might want to do strange things.
func PresetRootDirectory(root string) {
	cachedRootDir = root
}

func RootDirectory(create bool) (string, error) {
	if cachedRootDir != "" {
		return cachedRootDir, nil
	}

	root, _ := os.Executable()
	root = strings.ReplaceAll(root, "wireguard.exe", "")

	if !create {
		return filepath.Join(root, "Data"), nil
	}

	data := filepath.Join(root, "Data")

	_ = os.Mkdir(data, os.ModeDir|0777)

	cachedRootDir = data
	return cachedRootDir, nil
}
