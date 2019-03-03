/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package conf

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
