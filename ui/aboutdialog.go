/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2020 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"runtime"
	"strings"

	"github.com/lxn/walk"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/windows/l18n"
	"golang.zx2c4.com/wireguard/windows/version"
)

var easterEggIndex = -1
var showingAboutDialog *walk.Dialog

func onAbout(owner walk.Form) {
	showError(runAboutDialog(owner), owner)
}

func runAboutDialog(owner walk.Form) error {
	if showingAboutDialog != nil {
		showingAboutDialog.Show()
		raise(showingAboutDialog.Handle())
		return nil
	}

	vbl := walk.NewVBoxLayout()
	vbl.SetMargins(walk.Margins{80, 20, 80, 20})
	vbl.SetSpacing(10)

	var disposables walk.Disposables
	defer disposables.Treat()

	var err error
	showingAboutDialog, err = walk.NewDialogWithFixedSize(owner)
	if err != nil {
		return err
	}
	defer func() {
		showingAboutDialog = nil
	}()
	disposables.Add(showingAboutDialog)
	showingAboutDialog.SetTitle(l18n.Sprintf("About WireGuard"))
	showingAboutDialog.SetLayout(vbl)
	if icon, err := loadLogoIcon(32); err == nil {
		showingAboutDialog.SetIcon(icon)
	}

	font, _ := walk.NewFont("Segoe UI", 9, 0)
	showingAboutDialog.SetFont(font)

	iv, err := walk.NewImageView(showingAboutDialog)
	if err != nil {
		return err
	}
	iv.SetCursor(walk.CursorHand())
	iv.MouseUp().Attach(func(x, y int, button walk.MouseButton) {
		if button == walk.LeftButton {
			win.ShellExecute(showingAboutDialog.Handle(), nil, windows.StringToUTF16Ptr("https://www.wireguard.com/"), nil, nil, win.SW_SHOWNORMAL)
		} else if easterEggIndex >= 0 && button == walk.RightButton {
			if icon, err := loadSystemIcon("moricons", int32(easterEggIndex), 128); err == nil {
				iv.SetImage(icon)
				easterEggIndex++
			} else {
				easterEggIndex = -1
				if logo, err := loadLogoIcon(128); err == nil {
					iv.SetImage(logo)
				}
			}
		}
	})
	if logo, err := loadLogoIcon(128); err == nil {
		iv.SetImage(logo)
	}
	iv.Accessibility().SetName(l18n.Sprintf("WireGuard logo image"))

	wgLbl, err := walk.NewTextLabel(showingAboutDialog)
	if err != nil {
		return err
	}
	wgFont, _ := walk.NewFont("Segoe UI", 16, walk.FontBold)
	wgLbl.SetFont(wgFont)
	wgLbl.SetTextAlignment(walk.AlignHCenterVNear)
	wgLbl.SetText("WireGuard")

	detailsLbl, err := walk.NewTextLabel(showingAboutDialog)
	if err != nil {
		return err
	}
	detailsLbl.SetTextAlignment(walk.AlignHCenterVNear)
	detailsLbl.SetText(l18n.Sprintf("App version: %s\nGo backend version: %s\nGo version: %s-%s\nOperating system: %s\nArchitecture: %s", version.Number, version.ProtoImplementation(), strings.TrimPrefix(runtime.Version(), "go"), runtime.GOARCH, version.OsName(), version.NativeArch()))

	copyrightLbl, err := walk.NewTextLabel(showingAboutDialog)
	if err != nil {
		return err
	}
	copyrightFont, _ := walk.NewFont("Segoe UI", 7, 0)
	copyrightLbl.SetFont(copyrightFont)
	copyrightLbl.SetTextAlignment(walk.AlignHCenterVNear)
	copyrightLbl.SetText("Copyright © 2015-2020 Jason A. Donenfeld. All Rights Reserved.")

	buttonCP, err := walk.NewComposite(showingAboutDialog)
	if err != nil {
		return err
	}
	hbl := walk.NewHBoxLayout()
	hbl.SetMargins(walk.Margins{VNear: 10})
	buttonCP.SetLayout(hbl)
	walk.NewHSpacer(buttonCP)
	closePB, err := walk.NewPushButton(buttonCP)
	if err != nil {
		return err
	}
	closePB.SetAlignment(walk.AlignHCenterVNear)
	closePB.SetText(l18n.Sprintf("Close"))
	closePB.Clicked().Attach(showingAboutDialog.Accept)
	donatePB, err := walk.NewPushButton(buttonCP)
	if err != nil {
		return err
	}
	donatePB.SetAlignment(walk.AlignHCenterVNear)
	donatePB.SetText(l18n.Sprintf("♥ &Donate!"))
	donatePB.Clicked().Attach(func() {
		if easterEggIndex == -1 {
			easterEggIndex = 0
		}
		win.ShellExecute(showingAboutDialog.Handle(), nil, windows.StringToUTF16Ptr("https://www.wireguard.com/donations/"), nil, nil, win.SW_SHOWNORMAL)
		showingAboutDialog.Accept()
	})
	walk.NewHSpacer(buttonCP)

	showingAboutDialog.SetDefaultButton(donatePB)
	showingAboutDialog.SetCancelButton(closePB)

	disposables.Spare()

	showingAboutDialog.Run()

	return nil
}
