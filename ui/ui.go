/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/lxn/walk"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/windows/service"
)

// #include "../version.h"
import "C"

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

	mtw, err := NewManageTunnelsWindow()
	if err != nil {
		panic(err)
	}

	tray, err := NewTray(mtw)
	if err != nil {
		panic(err)
	}

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

Copyright © 2015-2019 WireGuard LLC.
All Rights Reserved.`,
		C.WIREGUARD_WINDOWS_VERSION, device.WireGuardGoVersion))

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
