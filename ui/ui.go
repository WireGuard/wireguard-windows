/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/lxn/walk"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/windows/manager"
	"golang.zx2c4.com/wireguard/windows/version"
)

var noTrayAvailable = false
var shouldQuitManagerWhenExiting = false
var startTime = time.Now()

func RunUI() {
	runtime.LockOSThread()
	windows.SetProcessPriorityBoost(windows.CurrentProcess(), false)
	defer func() {
		if err := recover(); err != nil {
			showErrorCustom(nil, "Panic", fmt.Sprint(err, "\n\n", string(debug.Stack())))
			panic(err)
		}
	}()

	var (
		err  error
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
			if version.OsIsCore() {
				noTrayAvailable = true
				break
			}
			time.Sleep(time.Millisecond * 400)
		}
	}

	manager.IPCClientRegisterManagerStopping(func() {
		mtw.Synchronize(func() {
			walk.App().Exit(0)
		})
	})

	onUpdateNotification := func(updateState manager.UpdateState) {
		if updateState == manager.UpdateStateUnknown {
			return
		}
		mtw.Synchronize(func() {
			switch updateState {
			case manager.UpdateStateFoundUpdate:
				mtw.UpdateFound()
				if tray != nil {
					tray.UpdateFound()
				}
			case manager.UpdateStateUpdatesDisabledUnofficialBuild:
				mtw.SetTitle(mtw.Title() + " (unsigned build, no updates)")
			}
		})
	}
	manager.IPCClientRegisterUpdateFound(onUpdateNotification)
	go func() {
		updateState, err := manager.IPCClientUpdateState()
		if err == nil {
			onUpdateNotification(updateState)
		}
	}()

	if tray == nil {
		win.ShowWindow(mtw.Handle(), win.SW_MINIMIZE)
	}

	mtw.Run()
	if tray != nil {
		tray.Dispose()
	}
	mtw.Dispose()

	if shouldQuitManagerWhenExiting {
		_, err := manager.IPCClientQuit(true)
		if err != nil {
			showErrorCustom(nil, "Error Exiting WireGuard", fmt.Sprintf("Unable to exit service due to: %v. You may want to stop WireGuard from the service manager.", err))
		}
	}
}

func onQuit() {
	shouldQuitManagerWhenExiting = true
	walk.App().Exit(0)
}

func showError(err error, owner walk.Form) bool {
	if err == nil {
		return false
	}

	showErrorCustom(owner, "Error", err.Error())

	return true
}

func showErrorCustom(owner walk.Form, title, message string) {
	walk.MsgBox(owner, title, message, walk.MsgBoxIconError)
}

func showWarningCustom(owner walk.Form, title, message string) {
	walk.MsgBox(owner, title, message, walk.MsgBoxIconWarning)
}
