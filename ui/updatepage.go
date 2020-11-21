/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2020 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"github.com/lxn/walk"

	"golang.zx2c4.com/wireguard/windows/l18n"
	"golang.zx2c4.com/wireguard/windows/manager"
	"golang.zx2c4.com/wireguard/windows/updater"
)

type UpdatePage struct {
	*walk.TabPage
}

func NewUpdatePage() (*UpdatePage, error) {
	var err error
	var disposables walk.Disposables
	defer disposables.Treat()

	up := &UpdatePage{}

	if up.TabPage, err = walk.NewTabPage(); err != nil {
		return nil, err
	}
	disposables.Add(up)

	up.SetTitle(l18n.Sprintf("An Update is Available!"))

	tabIcon, _ := loadSystemIcon("imageres", 1, 16)
	up.SetImage(tabIcon)

	up.SetLayout(walk.NewVBoxLayout())

	instructions, err := walk.NewTextLabel(up)
	if err != nil {
		return nil, err
	}
	instructions.SetText(l18n.Sprintf("An update to WireGuard is available. It is highly advisable to update without delay."))
	instructions.SetMinMaxSize(walk.Size{1, 0}, walk.Size{0, 0})

	status, err := walk.NewTextLabel(up)
	if err != nil {
		return nil, err
	}
	status.SetText(l18n.Sprintf("Status: Waiting for user"))
	status.SetMinMaxSize(walk.Size{1, 0}, walk.Size{0, 0})

	bar, err := walk.NewProgressBar(up)
	if err != nil {
		return nil, err
	}
	bar.SetVisible(false)

	button, err := walk.NewPushButton(up)
	if err != nil {
		return nil, err
	}
	updateIcon, _ := loadSystemIcon("shell32", -47, 32)
	button.SetImage(updateIcon)
	button.SetText(l18n.Sprintf("Update Now"))

	walk.NewVSpacer(up)

	switchToUpdatingState := func() {
		if !bar.Visible() {
			up.SetSuspended(true)
			button.SetEnabled(false)
			button.SetVisible(false)
			bar.SetVisible(true)
			bar.SetMarqueeMode(true)
			up.SetSuspended(false)
			status.SetText(l18n.Sprintf("Status: Waiting for updater service"))
		}
	}

	switchToReadyState := func() {
		if bar.Visible() {
			up.SetSuspended(true)
			bar.SetVisible(false)
			bar.SetValue(0)
			bar.SetRange(0, 1)
			bar.SetMarqueeMode(false)
			button.SetVisible(true)
			button.SetEnabled(true)
			up.SetSuspended(false)
		}
	}

	button.Clicked().Attach(func() {
		switchToUpdatingState()
		err := manager.IPCClientUpdate()
		if err != nil {
			switchToReadyState()
			status.SetText(l18n.Sprintf("Error: %v. Please try again.", err))
		}
	})

	manager.IPCClientRegisterUpdateProgress(func(dp updater.DownloadProgress) {
		up.Synchronize(func() {
			switchToUpdatingState()
			if dp.Error != nil {
				switchToReadyState()
				err := dp.Error
				status.SetText(l18n.Sprintf("Error: %v. Please try again.", err))
				return
			}
			if len(dp.Activity) > 0 {
				stateText := dp.Activity
				status.SetText(l18n.Sprintf("Status: %s", stateText))
			}
			if dp.BytesTotal > 0 {
				bar.SetMarqueeMode(false)
				bar.SetRange(0, int(dp.BytesTotal))
				bar.SetValue(int(dp.BytesDownloaded))
			} else {
				bar.SetMarqueeMode(true)
				bar.SetValue(0)
				bar.SetRange(0, 1)
			}
			if dp.Complete {
				switchToReadyState()
				status.SetText(l18n.Sprintf("Status: Complete!"))
				return
			}
		})
	})

	disposables.Spare()

	return up, nil
}
