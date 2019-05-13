/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/lxn/walk"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/windows/version"
)

var easterEggIndex = -1

func onAbout(owner walk.Form) {
	vbl := walk.NewVBoxLayout()
	vbl.SetMargins(walk.Margins{80, 20, 80, 20})
	vbl.SetSpacing(10)

	dlg, _ := walk.NewDialogWithFixedSize(owner)
	dlg.SetTitle("About WireGuard")
	dlg.SetLayout(vbl)
	if icon, err := loadLogoIcon(dlg.DPI() / 3); err == nil { //TODO: calculate DPI dynamically
		dlg.SetIcon(icon)
	}

	font, _ := walk.NewFont("Segoe UI", 9, 0)
	dlg.SetFont(font)

	iv, _ := walk.NewImageView(dlg)
	iv.SetCursor(walk.CursorHand())
	iv.MouseUp().Attach(func(x, y int, button walk.MouseButton) {
		if button == walk.LeftButton {
			win.ShellExecute(dlg.Handle(), nil, windows.StringToUTF16Ptr("https://www.wireguard.com/"), nil, nil, win.SW_SHOWNORMAL)
		} else if easterEggIndex >= 0 && button == walk.RightButton {
			if icon, err := loadSystemIcon("moricons", int32(easterEggIndex), dlg.DPI()*4/3); err == nil { //TODO: calculate DPI dynamically
				iv.SetImage(icon)
				easterEggIndex++
			} else {
				easterEggIndex = -1
				if logo, err := loadLogoIcon(dlg.DPI() * 4 / 3); err == nil { //TODO: calculate DPI dynamically
					iv.SetImage(logo)
				}
			}
		}
	})
	if logo, err := loadLogoIcon(dlg.DPI() * 4 / 3); err == nil { //TODO: calculate DPI dynamically
		iv.SetImage(logo)
	}

	wgLbl, _ := walk.NewTextLabel(dlg)
	wgFont, _ := walk.NewFont("Segoe UI", 16, walk.FontBold)
	wgLbl.SetFont(wgFont)
	wgLbl.SetTextAlignment(walk.AlignHCenterVNear)
	wgLbl.SetText("WireGuard")

	detailsLbl, _ := walk.NewTextLabel(dlg)
	detailsLbl.SetTextAlignment(walk.AlignHCenterVNear)
	detailsLbl.SetText(fmt.Sprintf("App version: %s\nGo backend version: %s\nGo version: %s\nOperating system: %s\nArchitecture: %s", version.RunningVersion(), device.WireGuardGoVersion, strings.TrimPrefix(runtime.Version(), "go"), version.OsName(), runtime.GOARCH))

	copyrightLbl, _ := walk.NewTextLabel(dlg)
	copyrightFont, _ := walk.NewFont("Segoe UI", 7, 0)
	copyrightLbl.SetFont(copyrightFont)
	copyrightLbl.SetTextAlignment(walk.AlignHCenterVNear)
	copyrightLbl.SetText("Copyright © 2015-2019 Jason A. Donenfeld. All Rights Reserved.")

	buttonCP, _ := walk.NewComposite(dlg)
	hbl := walk.NewHBoxLayout()
	hbl.SetMargins(walk.Margins{VNear: 10})
	buttonCP.SetLayout(hbl)
	walk.NewHSpacer(buttonCP)
	closePB, _ := walk.NewPushButton(buttonCP)
	closePB.SetAlignment(walk.AlignHCenterVNear)
	closePB.SetText("Close")
	closePB.Clicked().Attach(func() {
		dlg.Accept()
	})
	donatePB, _ := walk.NewPushButton(buttonCP)
	donatePB.SetAlignment(walk.AlignHCenterVNear)
	donatePB.SetText("♥ Donate!")
	donatePB.Clicked().Attach(func() {
		if easterEggIndex == -1 {
			easterEggIndex = 0
		}
		win.ShellExecute(dlg.Handle(), nil, windows.StringToUTF16Ptr("https://www.wireguard.com/donations/"), nil, nil, win.SW_SHOWNORMAL)
		dlg.Accept()
	})
	walk.NewHSpacer(buttonCP)

	dlg.SetDefaultButton(donatePB)
	dlg.SetCancelButton(closePB)

	dlg.Run()
}
