/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"github.com/lxn/walk"
	"github.com/lxn/win"
	"golang.zx2c4.com/wireguard/windows/service"
)

type ManageTunnelsWindow struct {
	*walk.MainWindow

	tunnelsPage *TunnelsPage
	logPage     *LogPage

	tunnelChangedCB *service.TunnelChangeCallback
}

func NewManageTunnelsWindow() (*ManageTunnelsWindow, error) {
	var err error

	var disposables walk.Disposables
	defer disposables.Treat()

	mtw := &ManageTunnelsWindow{}

	mtw.MainWindow, err = walk.NewMainWindowWithName("WireGuard")
	if err != nil {
		return nil, err
	}
	disposables.Add(mtw)

	mtw.SetIcon(iconProvider.baseIcon)
	mtw.SetTitle("WireGuard")
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

	mtw.logPage, _ = NewLogPage()
	tabWidget.Pages().Add(mtw.logPage.TabPage)

	disposables.Spare()

	mtw.tunnelChangedCB = service.IPCClientRegisterTunnelChange(mtw.onTunnelChange)
	mtw.onTunnelChange(nil, service.TunnelUnknown, nil)

	return mtw, nil
}

func (mtw *ManageTunnelsWindow) Dispose() {
	if mtw.tunnelChangedCB != nil {
		mtw.tunnelChangedCB.Unregister()
		mtw.tunnelChangedCB = nil
	}
	mtw.MainWindow.Dispose()
}

func (mtw *ManageTunnelsWindow) onTunnelChange(tunnel *service.Tunnel, state service.TunnelState, err error) {
	globalState, err2 := service.IPCClientGlobalState()
	mtw.Synchronize(func() {
		if err2 == nil {
			icon, err2 := iconProvider.IconWithOverlayForState(globalState)
			if err2 == nil {
				mtw.SetIcon(icon)
			}
		}

		if err != nil && mtw.Visible() {
			errMsg := err.Error()
			if len(errMsg) > 0 && errMsg[len(errMsg)-1] != '.' {
				errMsg += "."
			}
			walk.MsgBox(mtw, "Tunnel Error", errMsg+"\n\nPlease consult the log for more information.", walk.MsgBoxIconWarning)
		}
	})
}
