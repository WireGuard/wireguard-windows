// +build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"os"
	"path/filepath"
)

func tunnelConfigurationsDirectory() (string, error) {
	if cachedConfigFileDir != "" {
		return cachedConfigFileDir, nil
	}
	root, err := RootDirectory()
	if err != nil {
		return "", err
	}
	// on linux the configs are just in /etc/wireguard
	cachedConfigFileDir = root
	return cachedConfigFileDir, nil
}

func RootDirectory() (string, error) {
	if cachedRootDir != "" {
		return cachedRootDir, nil
	}
	c := filepath.Join("/etc", "wireguard")
	err := os.MkdirAll(c, os.ModeDir|0700)
	if err != nil {
		return "", err
	}
	cachedRootDir = c
	return cachedRootDir, nil
}
