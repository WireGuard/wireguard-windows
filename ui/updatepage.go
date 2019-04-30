/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"fmt"
	"golang.zx2c4.com/wireguard/windows/updater"

	"github.com/lxn/walk"
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
	up.SetImage(iconProvider.updateAvailableImage)
	//TODO: make title bold
	up.SetLayout(walk.NewVBoxLayout())
	up.Layout().SetMargins(walk.Margins{18, 18, 18, 18})

	instructions, _ := walk.NewTextLabel(up)
	instructions.SetText("An update to WireGuard is available. It is highly advisable to update without delay.")
	instructions.SetMinMaxSize(walk.Size{1, 0}, walk.Size{0, 0})

	status, _ := walk.NewTextLabel(up)
	status.SetText("Status: Waiting for user")
	status.SetMinMaxSize(walk.Size{1, 0}, walk.Size{0, 0})

	bar, _ := walk.NewProgressBar(up)
	bar.SetVisible(false)

	button, _ := walk.NewPushButton(up)
	button.SetText("Update Now")

	walk.NewVSpacer(up)

	button.Clicked().Attach(func() {
		up.SetSuspended(true)
		button.SetEnabled(false)
		button.SetVisible(false)
		bar.SetVisible(true)
		bar.SetMarqueeMode(true)
		up.SetSuspended(false)
		progress := updater.DownloadVerifyAndExecute()
		go func() {
			for {
				dp := <-progress
				retNow := false
				up.Synchronize(func() {
					if dp.Error != nil {
						up.SetSuspended(true)
						bar.SetVisible(false)
						bar.SetValue(0)
						bar.SetRange(0, 1)
						bar.SetMarqueeMode(false)
						button.SetVisible(true)
						button.SetEnabled(true)
						status.SetText(fmt.Sprintf("Error: %v. Please try again.", dp.Error))
						up.SetSuspended(false)
						retNow = true
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
						up.SetSuspended(true)
						bar.SetVisible(false)
						bar.SetValue(0)
						bar.SetRange(0, 0)
						bar.SetMarqueeMode(false)
						button.SetVisible(true)
						button.SetEnabled(true)
						status.SetText("Status: Complete!")
						up.SetSuspended(false)
						retNow = true
						return
					}
				})
				if retNow {
					return
				}
			}
		}()
	})
	return up, nil
}
