/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package conf

type storeCallback struct {
	cb func()
}

var storeCallbacks = make(map[*storeCallback]bool)

func RegisterStoreChangeCallback(cb func()) *storeCallback {
	startWatchingConfigDir()
	cb()
	s := &storeCallback{cb}
	storeCallbacks[s] = true
	return s
}

func UnregisterStoreChangeCallback(cb *storeCallback) {
	delete(storeCallbacks, cb)
}
