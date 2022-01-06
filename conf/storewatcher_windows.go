/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"log"

	"golang.org/x/sys/windows"
)

var haveStartedWatchingConfigDir bool

func startWatchingConfigDir() {
	if haveStartedWatchingConfigDir {
		return
	}
	haveStartedWatchingConfigDir = true
	go func() {
		h := windows.InvalidHandle
		defer func() {
			if h != windows.InvalidHandle {
				windows.FindCloseChangeNotification(h)
			}
			haveStartedWatchingConfigDir = false
		}()
	startover:
		configFileDir, err := tunnelConfigurationsDirectory()
		if err != nil {
			return
		}
		h, err = windows.FindFirstChangeNotification(configFileDir, true, windows.FILE_NOTIFY_CHANGE_FILE_NAME|windows.FILE_NOTIFY_CHANGE_DIR_NAME|windows.FILE_NOTIFY_CHANGE_ATTRIBUTES|windows.FILE_NOTIFY_CHANGE_SIZE|windows.FILE_NOTIFY_CHANGE_LAST_WRITE|windows.FILE_NOTIFY_CHANGE_LAST_ACCESS|windows.FILE_NOTIFY_CHANGE_CREATION|windows.FILE_NOTIFY_CHANGE_SECURITY)
		if err != nil {
			log.Printf("Unable to monitor config directory: %v", err)
			return
		}
		for {
			s, err := windows.WaitForSingleObject(h, windows.INFINITE)
			if err != nil || s == windows.WAIT_FAILED {
				log.Printf("Unable to wait on config directory watcher: %v", err)
				windows.FindCloseChangeNotification(h)
				h = windows.InvalidHandle
				goto startover
			}

			for cb := range storeCallbacks {
				cb.cb()
			}

			err = windows.FindNextChangeNotification(h)
			if err != nil {
				log.Printf("Unable to monitor config directory again: %v", err)
				windows.FindCloseChangeNotification(h)
				h = windows.InvalidHandle
				goto startover
			}
		}
	}()
}
