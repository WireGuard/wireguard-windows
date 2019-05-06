/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package service

import (
	"golang.zx2c4.com/wireguard/windows/updater"
	"golang.zx2c4.com/wireguard/windows/version"
	"log"
	"time"
)

type UpdateState uint32

const (
	UpdateStateUnknown UpdateState = iota
	UpdateStateFoundUpdate
	UpdateStateUpdatesDisabledUnofficialBuild
)

var updateState = UpdateStateUnknown

func checkForUpdates() {
	if !version.IsRunningOfficialVersion() {
		log.Println("Build is not official, so updates are disabled")
		updateState = UpdateStateUpdatesDisabledUnofficialBuild
		IPCServerNotifyUpdateFound(updateState)
		return
	}

	time.Sleep(time.Second * 10)

	first := true
	for {
		update, err := updater.CheckForUpdate()
		if err == nil && update != nil {
			log.Println("An update is available")
			updateState = UpdateStateFoundUpdate
			IPCServerNotifyUpdateFound(updateState)
			return
		}
		if err != nil {
			log.Printf("Update checker: %v", err)
			if first {
				time.Sleep(time.Minute * 4)
				first = false
			} else {
				time.Sleep(time.Minute * 25)
			}
		} else {
			time.Sleep(time.Hour)
		}
	}
}
