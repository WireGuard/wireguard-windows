/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package winipcfg

import (
	"sync"

	"golang.org/x/sys/windows"
)

// InterfaceChangeCallback structure allows interface change callback handling.
type InterfaceChangeCallback struct {
	cb func(notificationType MibNotificationType, iface *MibIPInterfaceRow)
}

var (
	interfaceChangeMutex     = sync.Mutex{}
	interfaceChangeCallbacks = make(map[*InterfaceChangeCallback]bool)
	interfaceChangeHandle    = windows.Handle(0)
)

// RegisterInterfaceChangeCallback registers a new InterfaceChangeCallback. If this particular callback is already
// registered, the function will silently return. Returned InterfaceChangeCallback.Unregister method should be used
// to unregister.
func RegisterInterfaceChangeCallback(callback func(notificationType MibNotificationType, iface *MibIPInterfaceRow)) (*InterfaceChangeCallback, error) {
	cb := &InterfaceChangeCallback{callback}

	interfaceChangeMutex.Lock()
	defer interfaceChangeMutex.Unlock()

	interfaceChangeCallbacks[cb] = true

	if interfaceChangeHandle == 0 {
		err := notifyIPInterfaceChange(windows.AF_UNSPEC, windows.NewCallback(interfaceChanged), 0, false, &interfaceChangeHandle)
		if err != nil {
			delete(interfaceChangeCallbacks, cb)
			interfaceChangeHandle = 0
			return nil, err
		}
	}

	return cb, nil
}

// Unregister unregisters the callback.
func (callback *InterfaceChangeCallback) Unregister() error {
	interfaceChangeMutex.Lock()
	defer interfaceChangeMutex.Unlock()

	delete(interfaceChangeCallbacks, callback)

	if len(interfaceChangeCallbacks) < 1 && interfaceChangeHandle != 0 {
		err := cancelMibChangeNotify2(interfaceChangeHandle)
		if err != nil {
			return err
		}
		interfaceChangeHandle = 0
	}

	return nil
}

func interfaceChanged(callerContext uintptr, row *MibIPInterfaceRow, notificationType MibNotificationType) uintptr {
	interfaceChangeMutex.Lock()
	for cb := range interfaceChangeCallbacks {
		cb.cb(notificationType, row)
	}
	interfaceChangeMutex.Unlock()
	return 0
}
