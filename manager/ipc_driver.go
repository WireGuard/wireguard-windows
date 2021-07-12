/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"sync"

	"golang.zx2c4.com/wireguard/windows/driver"
)

type lockedDriverAdapter struct {
	*driver.Adapter
	sync.Mutex
}

var driverAdapters = make(map[string]*lockedDriverAdapter)
var driverAdaptersLock sync.RWMutex

func findDriverAdapter(tunnelName string) (*lockedDriverAdapter, error) {
	driverAdaptersLock.RLock()
	driverAdapter, ok := driverAdapters[tunnelName]
	if ok {
		driverAdapter.Lock()
		driverAdaptersLock.RUnlock()
		return driverAdapter, nil
	}
	driverAdaptersLock.RUnlock()
	driverAdaptersLock.Lock()
	defer driverAdaptersLock.Unlock()
	driverAdapter, ok = driverAdapters[tunnelName]
	if ok {
		driverAdapter.Lock()
		return driverAdapter, nil
	}
	driverAdapter = &lockedDriverAdapter{}
	var err error
	driverAdapter.Adapter, err = driver.DefaultPool.OpenAdapter(tunnelName)
	if err != nil {
		return nil, err
	}
	driverAdapters[tunnelName] = driverAdapter
	driverAdapter.Lock()
	return driverAdapter, nil
}

func releaseDriverAdapter(tunnelName string) {
	driverAdaptersLock.Lock()
	defer driverAdaptersLock.Unlock()
	driverAdapter, ok := driverAdapters[tunnelName]
	if !ok {
		return
	}
	driverAdapter.Lock()
	delete(driverAdapters, tunnelName)
	driverAdapter.Unlock()
}
