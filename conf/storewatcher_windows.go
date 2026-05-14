/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"log"
	"time"

	"golang.org/x/sys/windows"
)

func startWatchingConfigDir() {
	go func() {
		h := windows.InvalidHandle
		defer func() {
			if h != windows.InvalidHandle {
				windows.FindCloseChangeNotification(h)
			}
		}()
	startover:
		configFileDir, err := tunnelConfigurationsDirectory()
		if err != nil {
			log.Printf("Unable to resolve config directory: %v", err)
			time.Sleep(time.Second)
			goto startover
		}
		h, err = windows.FindFirstChangeNotification(configFileDir, true, windows.FILE_NOTIFY_CHANGE_FILE_NAME|windows.FILE_NOTIFY_CHANGE_DIR_NAME|windows.FILE_NOTIFY_CHANGE_ATTRIBUTES|windows.FILE_NOTIFY_CHANGE_SIZE|windows.FILE_NOTIFY_CHANGE_LAST_WRITE|windows.FILE_NOTIFY_CHANGE_LAST_ACCESS|windows.FILE_NOTIFY_CHANGE_CREATION|windows.FILE_NOTIFY_CHANGE_SECURITY)
		if err != nil {
			log.Printf("Unable to monitor config directory: %v", err)
			time.Sleep(time.Second)
			goto startover
		}
		for {
			s, err := windows.WaitForSingleObject(h, windows.INFINITE)
			if err != nil || s == windows.WAIT_FAILED {
				log.Printf("Unable to wait on config directory watcher: %v", err)
				windows.FindCloseChangeNotification(h)
				h = windows.InvalidHandle
				goto startover
			}

			storeCallbacksLock.RLock()
			for cb := range storeCallbacks {
				cb.cb()
			}
			storeCallbacksLock.RUnlock()

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
