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
)

type UpdatePage struct {
	*walk.TabPage
}

func NewUpdatePage() (*UpdatePage, error) {
	up := &UpdatePage{}
	var err error

	if up.TabPage, err = walk.NewTabPage(); err != nil {
		return nil, err
	}

	up.SetTitle("An Update is Available!")

	tabIcon, _ := loadSystemIcon("imageres", 1, 16)
	up.SetImage(tabIcon)

	up.SetLayout(walk.NewVBoxLayout())

	instructions, _ := walk.NewTextLabel(up)
	instructions.SetText("An update to WireGuard is available. It is highly advisable to update without delay.")
	instructions.SetMinMaxSize(walk.Size{1, 0}, walk.Size{0, 0})

	status, _ := walk.NewTextLabel(up)
	status.SetText("Status: Waiting for user")
	status.SetMinMaxSize(walk.Size{1, 0}, walk.Size{0, 0})

	bar, _ := walk.NewProgressBar(up)
	bar.SetVisible(false)

	button, _ := walk.NewPushButton(up)
	updateIcon, _ := loadSystemIcon("shell32", 46, bar.Height())
	button.SetImage(updateIcon)
	button.SetText("Update Now")

	walk.NewVSpacer(up)

	switchToUpdatingState := func() {
		if !bar.Visible() {
			up.SetSuspended(true)
			button.SetEnabled(false)
			button.SetVisible(false)
			bar.SetVisible(true)
			bar.SetMarqueeMode(true)
			up.SetSuspended(false)
			status.SetText("Status: Waiting for updater service")
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
		err := service.IPCClientUpdate()
		if err != nil {
			switchToReadyState()
			status.SetText(fmt.Sprintf("Error: %v. Please try again.", err))
		}
	})

	service.IPCClientRegisterUpdateProgress(func(dp updater.DownloadProgress) {
		up.Synchronize(func() {
			switchToUpdatingState()
			if dp.Error != nil {
				switchToReadyState()
				status.SetText(fmt.Sprintf("Error: %v. Please try again.", dp.Error))
				return
			}
			if len(dp.Activity) > 0 {
				status.SetText(fmt.Sprintf("Status: %s", dp.Activity))
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
				status.SetText("Status: Complete!")
				return
			}
		})
	})

	return up, nil
}
