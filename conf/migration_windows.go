/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

var migrating sync.Mutex
var lastMigrationTimer *time.Timer

type MigrationCallback func(name, oldPath, newPath string)

func MigrateUnencryptedConfigs(migrated MigrationCallback) { migrateUnencryptedConfigs(3, migrated) }

func migrateUnencryptedConfigs(sharingBase int, migrated MigrationCallback) {
	if migrated == nil {
		migrated = func(_, _, _ string) {}
	}
	migrating.Lock()
	defer migrating.Unlock()
	configFileDir, err := tunnelConfigurationsDirectory()
	if err != nil {
		return
	}
	files, err := os.ReadDir(configFileDir)
	if err != nil {
		return
	}
	ignoreSharingViolations := false
	for _, file := range files {
		path := filepath.Join(configFileDir, file.Name())
		name := filepath.Base(file.Name())
		if len(name) <= len(configFileUnencryptedSuffix) || !strings.HasSuffix(name, configFileUnencryptedSuffix) {
			continue
		}
		if !file.Type().IsRegular() {
			continue
		}
		info, err := file.Info()
		if err != nil {
			continue
		}
		if info.Mode().Perm()&0444 == 0 {
			continue
		}

		var bytes []byte
		var config *Config
		var newPath string
		// We don't use os.ReadFile, because we actually want RDWR, so that we can take advantage
		// of Windows file locking for ensuring the file is finished being written.
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
				if ignoreSharingViolations {
					continue
				} else if sharingBase > 0 {
					if lastMigrationTimer != nil {
						lastMigrationTimer.Stop()
					}
					lastMigrationTimer = time.AfterFunc(time.Second/time.Duration(sharingBase*sharingBase), func() { migrateUnencryptedConfigs(sharingBase-1, migrated) })
					ignoreSharingViolations = true
					continue
				}
			}
			goto error
		}
		bytes, err = io.ReadAll(f)
		f.Close()
		if err != nil {
			goto error
		}
		config, err = FromWgQuickWithUnknownEncoding(string(bytes), strings.TrimSuffix(name, configFileUnencryptedSuffix))
		if err != nil {
			goto error
		}
		err = config.Save(true)
		if err != nil {
			goto error
		}
		err = os.Remove(path)
		if err != nil {
			goto error
		}
		newPath, err = config.Path()
		if err != nil {
			goto error
		}
		migrated(config.Name, path, newPath)
		continue
	error:
		log.Printf("Unable to ingest and encrypt %#q: %v", path, err)
	}
}
