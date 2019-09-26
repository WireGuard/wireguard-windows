/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package winipcfg

import (
	"sync"

	"golang.org/x/sys/windows"
)

// UnicastAddressChangeCallback structure allows unicast address change callback handling.
type UnicastAddressChangeCallback struct {
	cb func(notificationType MibNotificationType, addr *MibUnicastIPAddressRow)
}

var (
	unicastAddressChangeMutex     = sync.Mutex{}
	unicastAddressChangeCallbacks = make(map[*UnicastAddressChangeCallback]bool)
	unicastAddressChangeHandle    = windows.Handle(0)
)

// RegisterUnicastAddressChangeCallback registers a new UnicastAddressChangeCallback. If this particular callback is already
// registered, the function will silently return. Returned UnicastAddressChangeCallback.Unregister method should be used
// to unregister.
func RegisterUnicastAddressChangeCallback(callback func(notificationType MibNotificationType, addr *MibUnicastIPAddressRow)) (*UnicastAddressChangeCallback, error) {
	cb := &UnicastAddressChangeCallback{callback}

	unicastAddressChangeMutex.Lock()
	defer unicastAddressChangeMutex.Unlock()

	unicastAddressChangeCallbacks[cb] = true

	if unicastAddressChangeHandle == 0 {
		err := notifyUnicastIPAddressChange(windows.AF_UNSPEC, windows.NewCallback(unicastAddressChanged), 0, false, &unicastAddressChangeHandle)
		if err != nil {
			delete(unicastAddressChangeCallbacks, cb)
			unicastAddressChangeHandle = 0
			return nil, err
		}
	}

	return cb, nil
}

// Unregister unregisters the callback.
func (callback *UnicastAddressChangeCallback) Unregister() error {
	unicastAddressChangeMutex.Lock()
	defer unicastAddressChangeMutex.Unlock()

	delete(unicastAddressChangeCallbacks, callback)

	if len(unicastAddressChangeCallbacks) < 1 && unicastAddressChangeHandle != 0 {
		err := cancelMibChangeNotify2(unicastAddressChangeHandle)
		if err != nil {
			return err
		}
		unicastAddressChangeHandle = 0
	}

	return nil
}

func unicastAddressChanged(callerContext uintptr, row *MibUnicastIPAddressRow, notificationType MibNotificationType) uintptr {
	rowCopy := *row
	unicastAddressChangeMutex.Lock()
	for cb := range unicastAddressChangeCallbacks {
		go cb.cb(notificationType, &rowCopy)
	}
	unicastAddressChangeMutex.Unlock()
	return 0
}
