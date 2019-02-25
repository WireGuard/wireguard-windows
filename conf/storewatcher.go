/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package conf

import "reflect"

type StoreCallback func()

var storeCallbacks []StoreCallback

func RegisterStoreChangeCallback(cb StoreCallback) {
	startWatchingConfigDir()
	cb()
	storeCallbacks = append(storeCallbacks, cb)
}

func UnregisterStoreChangeCallback(cb StoreCallback) {
	//TODO: this function is ridiculous, doing slow iteration like this and reflection too.

	index := -1
	for i, e := range storeCallbacks {
		if reflect.ValueOf(e).Pointer() == reflect.ValueOf(cb).Pointer() {
			index = i
			break
		}
	}
	if index == -1 {
		return
	}
	newList := storeCallbacks[0:index]
	if index < len(storeCallbacks)-1 {
		newList = append(newList, storeCallbacks[index+1:]...)
	}
	storeCallbacks = newList
}
