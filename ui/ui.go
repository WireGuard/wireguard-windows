/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"fmt"
	"github.com/lxn/walk"
	"golang.zx2c4.com/wireguard/windows/service"
	"golang.zx2c4.com/wireguard/windows/updater"
	"golang.zx2c4.com/wireguard/windows/version"
	"log"
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

	go func() {
		if !version.IsRunningOfficialVersion() {
			mtw.Synchronize(func() {
				mtw.SetTitle(mtw.Title() + " (unsigned build)")
			})
			return
		}

		first := true
		for {
			update, err := updater.CheckForUpdate()
			if err == nil && update != nil {
				mtw.Synchronize(func() {
					mtw.UpdateFound()
					tray.UpdateFound()
				})
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
