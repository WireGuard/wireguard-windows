/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func maybeMigrateConfiguration(c string) {
	if disableAutoMigration {
		return
	}
	oldRoot, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return
	}
	oldC := filepath.Join(oldRoot, "WireGuard", "Configurations")
	files, err := ioutil.ReadDir(oldC)
	if err != nil {
		return
	}
	for i := range files {
		if files[i].IsDir() {
			continue
		}
		fileName := files[i].Name()
		newPath := filepath.Join(c, fileName)
		newFile, err := os.OpenFile(newPath, os.O_EXCL|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			continue
		}
		oldPath := filepath.Join(oldC, fileName)
		oldConfig, err := ioutil.ReadFile(oldPath)
		if err != nil {
			newFile.Close()
			os.Remove(newPath)
			continue
		}
		_, err = newFile.Write(oldConfig)
		if err != nil {
			newFile.Close()
			os.Remove(newPath)
			continue
		}
		newFile.Close()
		os.Remove(oldPath)
		log.Printf("Migrated configuration from ‘%s’ to ‘%s’", oldPath, newPath)
	}
	if os.Remove(oldC) == nil {
		oldLog := filepath.Join(oldRoot, "WireGuard", "log.bin")
		oldRoot := filepath.Join(oldRoot, "WireGuard")
		os.Remove(oldLog)
		os.Remove(oldRoot)
	}
}
