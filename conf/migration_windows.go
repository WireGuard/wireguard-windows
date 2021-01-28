/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"errors"
	"io/ioutil"
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

func MigrateUnencryptedConfigs() { migrateUnencryptedConfigs(3) }

func migrateUnencryptedConfigs(sharingBase int) {
	migrating.Lock()
	defer migrating.Unlock()
	configFileDir, err := tunnelConfigurationsDirectory()
	if err != nil {
		return
	}
	files, err := ioutil.ReadDir(configFileDir)
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
		if !file.Mode().IsRegular() || file.Mode().Perm()&0444 == 0 {
			continue
		}

		var bytes []byte
		var config *Config
		// We don't use ioutil's ReadFile, because we actually want RDWR, so that we can take advantage
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
					lastMigrationTimer = time.AfterFunc(time.Second/time.Duration(sharingBase*sharingBase), func() { migrateUnencryptedConfigs(sharingBase - 1) })
					ignoreSharingViolations = true
					continue
				}
			}
			goto error
		}
		bytes, err = ioutil.ReadAll(f)
		f.Close()
		if err != nil {
			goto error
		}
		config, err = FromWgQuickWithUnknownEncoding(string(bytes), strings.TrimSuffix(name, configFileUnencryptedSuffix))
		if err != nil {
			goto error
		}
		err = config.Save(false)
		if err != nil {
			goto error
		}
		err = os.Remove(path)
		if err != nil {
			log.Printf("Unable to remove old path %#q: %v", path, err)
		}
		continue
	error:
		log.Printf("Unable to ingest and encrypt %#q: %v", path, err)
	}
}
