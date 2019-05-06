/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"fmt"
	"github.com/lxn/walk"
	"golang.zx2c4.com/wireguard/windows/service"
	"runtime"
	"runtime/debug"
	"time"
)

var iconProvider *IconProvider

var shouldQuitManagerWhenExiting = false

func RunUI() {
	runtime.LockOSThread()

	defer func() {
		if err := recover(); err != nil {
			walk.MsgBox(nil, "Panic", fmt.Sprint(err, "\n\n", string(debug.Stack())), walk.MsgBoxIconError)
			panic(err)
		}
	}()

	var err error

	var (
		mtw  *ManageTunnelsWindow
		tray *Tray
	)

	for mtw == nil {
		mtw, err = NewManageTunnelsWindow()
		if err != nil {
			time.Sleep(time.Millisecond * 400)
		}
	}

	for tray == nil {
		tray, err = NewTray(mtw)
		if err != nil {
			time.Sleep(time.Millisecond * 400)
		}
	}

	service.IPCClientRegisterManagerStopping(func() {
		mtw.Synchronize(func() {
			walk.App().Exit(0)
		})
	})

	onUpdateNotification := func(updateState service.UpdateState) {
		if updateState == service.UpdateStateUnknown {
			return
		}
		mtw.Synchronize(func() {
			switch updateState {
			case service.UpdateStateFoundUpdate:
				mtw.UpdateFound()
				tray.UpdateFound()
			case service.UpdateStateUpdatesDisabledUnofficialBuild:
				mtw.SetTitle(mtw.Title() + " (unsigned build, no updates)")
			}
		})
	}
	service.IPCClientRegisterUpdateFound(onUpdateNotification)
	go func() {
		updateState, err := service.IPCClientUpdateState()
		if err == nil {
			onUpdateNotification(updateState)
		}
	}()

	mtw.Starting().Attach(func() {
		mtw.tunnelsPage.SetFocus()
	})
	mtw.Run()
	tray.Dispose()
	mtw.Dispose()
	iconProvider.Dispose()

	if shouldQuitManagerWhenExiting {
		_, err := service.IPCClientQuit(true)
		if err != nil {
			walk.MsgBox(nil, "Error Exiting WireGuard", fmt.Sprintf("Unable to exit service due to: %s. You may want to stop WireGuard from the service manager.", err), walk.MsgBoxIconError)
		}
	}
}

func onQuit() {
	shouldQuitManagerWhenExiting = true
	walk.App().Exit(0)
}
