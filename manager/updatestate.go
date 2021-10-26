/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"log"
	unsafeRand "math/rand"
	"time"

	"golang.zx2c4.com/wireguard/windows/services"
	"golang.zx2c4.com/wireguard/windows/updater"
	"golang.zx2c4.com/wireguard/windows/version"
)

type UpdateState uint32

const (
	UpdateStateUnknown UpdateState = iota
	UpdateStateFoundUpdate
	UpdateStateUpdatesDisabledUnofficialBuild
)

var updateState = UpdateStateUnknown

func jitterSleep(min, max time.Duration) {
	time.Sleep(min + time.Duration(unsafeRand.Int63n(int64(max-min+1))))
}

func checkForUpdates() {
	if !version.IsRunningOfficialVersion() {
		log.Println("Build is not official, so updates are disabled")
		updateState = UpdateStateUpdatesDisabledUnofficialBuild
		IPCServerNotifyUpdateFound(updateState)
		return
	}
	if services.StartedAtBoot() {
		jitterSleep(time.Minute*2, time.Minute*5)
	}
	noError, didNotify := true, false
	for {
		update, err := updater.CheckForUpdate()
		if err == nil && update != nil && !didNotify {
			log.Println("An update is available")
			updateState = UpdateStateFoundUpdate
			IPCServerNotifyUpdateFound(updateState)
			didNotify = true
		} else if err != nil && !didNotify {
			log.Printf("Update checker: %v", err)
			if noError {
				jitterSleep(time.Minute*4, time.Minute*6)
				noError = false
			} else {
				jitterSleep(time.Minute*25, time.Minute*30)
			}
		} else {
			jitterSleep(time.Hour-time.Minute*3, time.Hour+time.Minute*3)
		}
	}
}
