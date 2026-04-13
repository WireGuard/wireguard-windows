/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package conf

import "sync"

type StoreCallback struct {
	cb func()
}

var (
	storeCallbacks     = make(map[*StoreCallback]bool)
	storeCallbacksLock sync.RWMutex
	watchConfigDirOnce sync.Once
)

func RegisterStoreChangeCallback(cb func()) *StoreCallback {
	watchConfigDirOnce.Do(startWatchingConfigDir)
	cb()
	s := &StoreCallback{cb}
	storeCallbacksLock.Lock()
	storeCallbacks[s] = true
	storeCallbacksLock.Unlock()
	return s
}

func (cb *StoreCallback) Unregister() {
	storeCallbacksLock.Lock()
	delete(storeCallbacks, cb)
	storeCallbacksLock.Unlock()
}
