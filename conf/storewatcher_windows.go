/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"log"

	"golang.org/x/sys/windows"
)

type StoreCallback struct {
	cb func()
}

var storeCallbacks = make(map[*StoreCallback]bool)

func RegisterStoreChangeCallback(cb func()) *StoreCallback {
	startWatchingConfigDir()
	cb()
	s := &StoreCallback{cb}
	storeCallbacks[s] = true
	return s
}

func (cb *StoreCallback) Unregister() {
	delete(storeCallbacks, cb)
}

const (
	fncFILE_NAME   uint32 = 0x00000001
	fncDIR_NAME    uint32 = 0x00000002
	fncATTRIBUTES  uint32 = 0x00000004
	fncSIZE        uint32 = 0x00000008
	fncLAST_WRITE  uint32 = 0x00000010
	fncLAST_ACCESS uint32 = 0x00000020
	fncCREATION    uint32 = 0x00000040
	fncSECURITY    uint32 = 0x00000100
)

//sys	findFirstChangeNotification(path *uint16, watchSubtree bool, filter uint32) (handle windows.Handle, err error) [failretval==windows.InvalidHandle] = kernel32.FindFirstChangeNotificationW
//sys	findNextChangeNotification(handle windows.Handle) (err error) = kernel32.FindNextChangeNotification

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
				windows.CloseHandle(h)
			}
			haveStartedWatchingConfigDir = false
		}()
	startover:
		configFileDir, err := tunnelConfigurationsDirectory()
		if err != nil {
			return
		}
		h, err = findFirstChangeNotification(windows.StringToUTF16Ptr(configFileDir), true, fncFILE_NAME|fncDIR_NAME|fncATTRIBUTES|fncSIZE|fncLAST_WRITE|fncLAST_ACCESS|fncCREATION|fncSECURITY)
		if err != nil {
			log.Printf("Unable to monitor config directory: %v", err)
			return
		}
		for {
			s, err := windows.WaitForSingleObject(h, windows.INFINITE)
			if err != nil || s == windows.WAIT_FAILED {
				log.Printf("Unable to wait on config directory watcher: %v", err)
				windows.CloseHandle(h)
				h = windows.InvalidHandle
				goto startover
			}

			for cb := range storeCallbacks {
				cb.cb()
			}

			err = findNextChangeNotification(h)
			if err != nil {
				log.Printf("Unable to monitor config directory again: %v", err)
				windows.CloseHandle(h)
				h = windows.InvalidHandle
				goto startover
			}
		}
	}()
}
