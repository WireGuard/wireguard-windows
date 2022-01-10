/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package services

import (
	"errors"
	"log"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.zx2c4.com/wireguard/windows/version"
)

var (
	startedAtBoot     bool
	startedAtBootOnce sync.Once
)

func StartedAtBoot() bool {
	startedAtBootOnce.Do(func() {
		if isService, err := svc.IsWindowsService(); err == nil && !isService {
			return
		}
		if reason, err := svc.DynamicStartReason(); err == nil {
			startedAtBoot = (reason&svc.StartReasonAuto) != 0 || (reason&svc.StartReasonDelayedAuto) != 0
		} else if errors.Is(err, windows.ERROR_PROC_NOT_FOUND) {
			// TODO: Below this line is Windows 7 compatibility code, which hopefully we can delete at some point.
			startedAtBoot = windows.DurationSinceBoot() < time.Minute*10
		} else {
			log.Printf("Unable to determine service start reason: %v", err)
		}
	})
	return startedAtBoot
}

func PrintStarting() {
	boot := ""
	if StartedAtBoot() {
		boot = " at boot"
	}
	log.Printf("Starting%s %s", boot, version.UserAgent())
}
