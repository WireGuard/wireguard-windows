/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/lxn/walk"
	"golang.zx2c4.com/wireguard/windows/ringlogger"
	"golang.zx2c4.com/wireguard/windows/service"
)

const nagMessage = `It looks like you're still using this WireGuard pre-alpha build. Great!

We're glad you like it, and we'd appreciate you sharing both your successes and your tribulations with us via team@wireguard.com or #wireguard on Freenode.

But because this is pre-release software, we're not confident it's something you should yet be using, except for testing and reporting bugs. Check back with us for a newer version.

Would you like to quit WireGuard now? If not, you'll be nagged again in two minutes about the same thing.`

func nag() {
	if walk.MsgBox(nil, "THANKS FOR REPORTING BUGS COME AGAIN ANOTHER DAY", nagMessage, walk.MsgBoxIconError|walk.MsgBoxYesNo|walk.MsgBoxSystemModal) != walk.DlgCmdNo {
		onQuit()
	}
	time.AfterFunc(time.Minute*2, nag)
}

func RunUI() {
	runtime.LockOSThread()

	logger, err := ringlogger.NewRingloggerFromInheritedMappingHandle(os.Args[5], "GUI")
	if err != nil {
		walk.MsgBox(nil, "Unable to initialize logging", fmt.Sprint(err), walk.MsgBoxIconError)
		return
	}

	tunnelTracker := new(TunnelTracker)

	icon, err := walk.NewIconFromResourceId(1)
	if err != nil {
		panic(err)
	}
	defer icon.Dispose()

	mtw, err := NewManageTunnelsWindow(icon, logger)
	if err != nil {
		panic(err)
	}
	defer mtw.Dispose()

	mtw.SetTunnelTracker(tunnelTracker)

	tray, err := NewTray(mtw, icon)
	if err != nil {
		panic(err)
	}
	defer tray.Dispose()

	// Bind to updates
	service.IPCClientRegisterTunnelChange(func(tunnel *service.Tunnel, state service.TunnelState, err error) {
		mtw.Synchronize(func() {
			tunnelTracker.SetTunnelState(tunnel, state, err)
			mtw.SetTunnelState(tunnel, state)
			tray.SetTunnelStateWithNotification(tunnel, state, err == nil)
		})

		if err == nil {
			return
		}

		if mtw.Visible() {
			errMsg := err.Error()
			if len(errMsg) > 0 && errMsg[len(errMsg)-1] != '.' {
				errMsg += "."
			}
			walk.MsgBox(mtw, "Tunnel Error", errMsg+"\n\nPlease consult the Windows Event Log for more information.", walk.MsgBoxIconWarning)
		} else {
			tray.ShowError("WireGuard Tunnel Error", err.Error())
		}
	})

	time.AfterFunc(time.Minute*15, nag)
	mtw.Run()
}

func onQuit() {
	_, err := service.IPCClientQuit(true)
	if err != nil {
		walk.MsgBox(nil, "Error Exiting WireGuard", fmt.Sprintf("Unable to exit service due to: %s. You may want to stop WireGuard from the service manager.", err), walk.MsgBoxIconError)
		os.Exit(1)
	}

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

Copyright © 2019 WireGuard LLC.
All Rights Reserved.`,
		"TODO", "TODO"))

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
