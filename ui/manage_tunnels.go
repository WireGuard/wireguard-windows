/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"github.com/lxn/walk"
	"github.com/lxn/win"
	"golang.zx2c4.com/wireguard/windows/ringlogger"
	"golang.zx2c4.com/wireguard/windows/service"
)

type ManageTunnelsWindow struct {
	*walk.MainWindow

	icon        *walk.Icon
	logger      *ringlogger.Ringlogger
	tunnelsPage *TunnelsPage
	logPage     *LogPage
}

func NewManageTunnelsWindow(icon *walk.Icon, logger *ringlogger.Ringlogger) (*ManageTunnelsWindow, error) {
	var err error

	var disposables walk.Disposables
	defer disposables.Treat()

	mtw := &ManageTunnelsWindow{
		icon:   icon,
		logger: logger,
	}
	mtw.MainWindow, err = walk.NewMainWindowWithName("WireGuard")
	if err != nil {
		return nil, err
	}
	disposables.Add(mtw)

	mtw.SetIcon(mtw.icon)
	mtw.SetTitle("Manage WireGuard Tunnels")
	font, err := walk.NewFont("Segoe UI", 9, 0)
	if err != nil {
		return nil, err
	}
	mtw.AddDisposable(font)
	mtw.SetFont(font)
	mtw.SetSize(walk.Size{900, 600})
	mtw.SetLayout(walk.NewVBoxLayout())
	mtw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		// "Close to tray" instead of exiting application
		onQuit()
	})
	mtw.VisibleChanged().Attach(func() {
		if mtw.Visible() {
			mtw.tunnelsPage.updateConfView()
			win.SetForegroundWindow(mtw.Handle())
			win.BringWindowToTop(mtw.Handle())

			mtw.logPage.scrollToBottom()
		}
	})

	tabWidget, _ := walk.NewTabWidget(mtw)

	mtw.tunnelsPage, _ = NewTunnelsPage()
	tabWidget.Pages().Add(mtw.tunnelsPage.TabPage)

	mtw.logPage, _ = NewLogPage(logger)
	tabWidget.Pages().Add(mtw.logPage.TabPage)

	disposables.Spare()

	return mtw, nil
}

func (mtw *ManageTunnelsWindow) TunnelTracker() *TunnelTracker {
	return mtw.tunnelsPage.tunnelTracker
}

func (mtw *ManageTunnelsWindow) SetTunnelTracker(tunnelTracker *TunnelTracker) {
	mtw.tunnelsPage.tunnelTracker = tunnelTracker

	mtw.tunnelsPage.confView.SetTunnelTracker(tunnelTracker)
}

func (mtw *ManageTunnelsWindow) SetTunnelState(tunnel *service.Tunnel, state service.TunnelState) {
	mtw.tunnelsPage.SetTunnelState(tunnel, state)

	icon, err := mtw.tunnelsPage.tunnelsView.imageProvider.IconWithOverlayForState(mtw.icon, state)
	if err != nil {
		return
	}

	mtw.SetIcon(icon)
}
