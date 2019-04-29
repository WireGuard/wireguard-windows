/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"fmt"
	"github.com/lxn/walk"
	"golang.zx2c4.com/wireguard/device"
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

	iconProvider, err = NewIconProvider()
	if err != nil {
		walk.MsgBox(nil, "Unable to initialize icon provider", fmt.Sprint(err), walk.MsgBoxIconError)
		return
	}

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

	go func() {
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

func onAbout(owner walk.Form) {
	vbl := walk.NewVBoxLayout()
	vbl.SetMargins(walk.Margins{80, 20, 80, 20})
	vbl.SetSpacing(10)

	dlg, _ := walk.NewDialogWithFixedSize(owner)
	dlg.SetTitle("About WireGuard")
	dlg.SetLayout(vbl)
	dlg.SetIcon(iconProvider.baseIcon)

	font, _ := walk.NewFont("Segoe UI", 9, 0)
	dlg.SetFont(font)

	icon, err := walk.NewIconFromResourceIdWithSize(1, walk.Size{128, 128})
	if err != nil {
		panic(err)
	}
	dlg.AddDisposable(icon)

	iv, _ := walk.NewImageView(dlg)
	iv.SetImage(icon)

	wgFont, _ := walk.NewFont("Segoe UI", 16, walk.FontBold)

	wgLbl, _ := walk.NewLabel(dlg)
	wgLbl.SetFont(wgFont)
	wgLbl.SetTextAlignment(walk.AlignCenter)
	wgLbl.SetText("WireGuard")

	detailsLbl, _ := walk.NewTextLabel(dlg)
	detailsLbl.SetTextAlignment(walk.AlignHCenterVNear)

	detailsLbl.SetText(fmt.Sprintf(`App version: %s
Go backend version: %s
Golang version: %s %s
%s

Copyright © 2015-2019 WireGuard LLC.
All Rights Reserved.`,
		version.WireGuardWindowsVersion, device.WireGuardGoVersion, runtime.Version(), runtime.GOARCH, version.OsName()))

	hbl := walk.NewHBoxLayout()
	hbl.SetMargins(walk.Margins{VNear: 10})

	buttonCP, _ := walk.NewComposite(dlg)
	buttonCP.SetLayout(hbl)

	walk.NewHSpacer(buttonCP)

	closePB, _ := walk.NewPushButton(buttonCP)
	closePB.SetAlignment(walk.AlignHCenterVNear)
	closePB.SetText("Close")
	closePB.Clicked().Attach(func() {
		dlg.Accept()
	})

	walk.NewHSpacer(buttonCP)

	dlg.SetDefaultButton(closePB)
	dlg.SetCancelButton(closePB)

	dlg.Run()
}
