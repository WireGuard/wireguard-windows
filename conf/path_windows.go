/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/windows/elevate"
)

func tunnelConfigurationsDirectory() (string, error) {
	if cachedConfigFileDir != "" {
		return cachedConfigFileDir, nil
	}
	root, err := RootDirectory()
	if err != nil {
		return "", err
	}
	c := filepath.Join(root, "Configurations")
	err = os.MkdirAll(c, os.ModeDir|0700)
	if err != nil {
		return "", err
	}
	maybeMigrateConfiguration(c)
	cachedConfigFileDir = c
	return cachedConfigFileDir, nil
}

func RootDirectory() (string, error) {
	if cachedRootDir != "" {
		return cachedRootDir, nil
	}
	root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_CREATE)
	if err != nil {
		return "", err
	}
	c := filepath.Join(root, "WireGuard")
	err = os.Mkdir(c, 0600)
	if err != nil && !os.IsExist(err) {
		return "", err
	}

	owner, group, dacl, err := elevate.GetDefaultObjectDacl()
	if err != nil {
		return "", err
	}
	//TODO: what about clearing preexisting SACL?
	//TODO: symlink mischief?
	err = windows.SetNamedSecurityInfo(c, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION|windows.ATTRIBUTE_SECURITY_INFORMATION, owner, group, dacl, nil)
	if err != nil {
		return "", err
	}
	cachedRootDir = c
	return cachedRootDir, nil
}
