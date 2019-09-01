/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package winipcfg

import (
	"sync"

	"golang.org/x/sys/windows"
)

// RouteChangeCallback structure allows route change callback handling.
type RouteChangeCallback struct {
	cb func(notificationType MibNotificationType, route *MibIPforwardRow2)
}

var (
	routeChangeAddRemoveMutex = sync.Mutex{}
	routeChangeMutex          = sync.Mutex{}
	routeChangeCallbacks      = make(map[*RouteChangeCallback]bool)
	routeChangeHandle         = windows.Handle(0)
)

// RegisterRouteChangeCallback registers a new RouteChangeCallback. If this particular callback is already
// registered, the function will silently return. Returned RouteChangeCallback.Unregister method should be used
// to unregister.
func RegisterRouteChangeCallback(callback func(notificationType MibNotificationType, route *MibIPforwardRow2)) (*RouteChangeCallback, error) {
	s := &RouteChangeCallback{callback}

	routeChangeAddRemoveMutex.Lock()
	defer routeChangeAddRemoveMutex.Unlock()

	routeChangeMutex.Lock()
	defer routeChangeMutex.Unlock()

	routeChangeCallbacks[s] = true

	if routeChangeHandle == 0 {
		err := notifyRouteChange2(windows.AF_UNSPEC, windows.NewCallback(routeChanged), 0, false, &routeChangeHandle)
		if err != nil {
			delete(routeChangeCallbacks, s)
			routeChangeHandle = 0
			return nil, err
		}
	}

	return s, nil
}

// Unregister unregisters the callback.
func (callback *RouteChangeCallback) Unregister() error {
	routeChangeAddRemoveMutex.Lock()
	defer routeChangeAddRemoveMutex.Unlock()

	routeChangeMutex.Lock()
	delete(routeChangeCallbacks, callback)
	removeIt := len(routeChangeCallbacks) == 0 && routeChangeHandle != 0
	routeChangeMutex.Unlock()

	if removeIt {
		err := cancelMibChangeNotify2(routeChangeHandle)
		if err != nil {
			return err
		}
		routeChangeHandle = 0
	}

	return nil
}

func routeChanged(callerContext uintptr, row *MibIPforwardRow2, notificationType MibNotificationType) uintptr {
	routeChangeMutex.Lock()
	for cb := range routeChangeCallbacks {
		go cb.cb(notificationType, row)
	}
	routeChangeMutex.Unlock()
	return 0
}
