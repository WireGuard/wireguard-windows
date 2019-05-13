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
	walk.FormBase

	tabs        *walk.TabWidget
	tunnelsPage *TunnelsPage
	logPage     *LogPage
	updatePage  *UpdatePage

	tunnelChangedCB *service.TunnelChangeCallback
}

const (
	manageWindowWindowClass = "WireGuard UI - Manage Tunnels"
	raiseMsg                = win.WM_USER + 0x3510
)

func init() {
	walk.MustRegisterWindowClass(manageWindowWindowClass)
}

func NewManageTunnelsWindow() (*ManageTunnelsWindow, error) {
	var err error

	font, err := walk.NewFont("Segoe UI", 9, 0)
	if err != nil {
		return nil, err
	}

	mtw := new(ManageTunnelsWindow)
	mtw.SetName("WireGuard")

	err = walk.InitWindow(mtw, nil, manageWindowWindowClass, win.WS_OVERLAPPEDWINDOW, win.WS_EX_CONTROLPARENT)
	if err != nil {
		return nil, err
	}
	win.ChangeWindowMessageFilterEx(mtw.Handle(), raiseMsg, win.MSGFLT_ALLOW, nil)
	mtw.SetPersistent(true)

	if icon, err := loadLogoIcon(mtw.DPI() / 3); err == nil { //TODO: calculate DPI dynamically
		mtw.SetIcon(icon)
	}
	mtw.SetTitle("WireGuard")
	mtw.AddDisposable(font)
	mtw.SetFont(font)
	mtw.SetSize(walk.Size{670, 525})
	mtw.SetMinMaxSize(walk.Size{500, 400}, walk.Size{0, 0})
	vlayout := walk.NewVBoxLayout()
	vlayout.SetMargins(walk.Margins{5, 5, 5, 5})
	mtw.SetLayout(vlayout)
	mtw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		// "Close to tray" instead of exiting application
		*canceled = true
		if !noTrayAvailable {
			mtw.Hide()
		} else {
			win.ShowWindow(mtw.Handle(), win.SW_MINIMIZE)
		}
	})
	mtw.VisibleChanged().Attach(func() {
		if mtw.Visible() {
			mtw.tunnelsPage.updateConfView()
			win.SetForegroundWindow(mtw.Handle())
			win.BringWindowToTop(mtw.Handle())
			mtw.logPage.scrollToBottom()
		}
	})

	mtw.tabs, _ = walk.NewTabWidget(mtw)

	if mtw.tunnelsPage, err = NewTunnelsPage(); err != nil {
		return nil, err
	}
	mtw.tabs.Pages().Add(mtw.tunnelsPage.TabPage)
	mtw.tunnelsPage.CreateToolbar()

	if mtw.logPage, err = NewLogPage(); err != nil {
		return nil, err
	}
	mtw.tabs.Pages().Add(mtw.logPage.TabPage)

	mtw.tunnelChangedCB = service.IPCClientRegisterTunnelChange(mtw.onTunnelChange)
	globalState, _ := service.IPCClientGlobalState()
	mtw.onTunnelChange(nil, service.TunnelUnknown, globalState, nil)

	return mtw, nil
}

func (mtw *ManageTunnelsWindow) Dispose() {
	if mtw.tunnelChangedCB != nil {
		mtw.tunnelChangedCB.Unregister()
		mtw.tunnelChangedCB = nil
	}
	mtw.FormBase.Dispose()
}

func (mtw *ManageTunnelsWindow) onTunnelChange(tunnel *service.Tunnel, state service.TunnelState, globalState service.TunnelState, err error) {
	mtw.Synchronize(func() {
		if pi := mtw.ProgressIndicator(); pi != nil {
			switch globalState {
			case service.TunnelStopping, service.TunnelStarting:
				pi.SetState(walk.PIIndeterminate)
			default:
				pi.SetState(walk.PINoProgress)
			}
		}

		icon, err2 := iconWithOverlayForState(globalState, mtw.DPI()/3) //TODO: calculate DPI dynamically
		if err2 == nil {
			mtw.SetIcon(icon)
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

func (mtw *ManageTunnelsWindow) UpdateFound() {
	if mtw.updatePage != nil {
		return
	}
	mtw.SetTitle(mtw.Title() + " (out of date)")
	updatePage, err := NewUpdatePage()
	if err == nil {
		mtw.updatePage = updatePage
		mtw.tabs.Pages().Add(updatePage.TabPage)
	}
}

func (mtw *ManageTunnelsWindow) WndProc(hwnd win.HWND, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case win.WM_QUERYENDSESSION:
		if lParam == win.ENDSESSION_CLOSEAPP {
			return win.TRUE
		}
	case win.WM_ENDSESSION:
		if lParam == win.ENDSESSION_CLOSEAPP && wParam == 1 {
			walk.App().Exit(198)
		}
	case raiseMsg:
		if !mtw.Visible() {
			mtw.tunnelsPage.listView.SelectFirstActiveTunnel()
			if mtw.tabs.Pages().Len() != 3 {
				mtw.tabs.SetCurrentIndex(0)
			}
		}
		if mtw.tabs.Pages().Len() == 3 {
			mtw.tabs.SetCurrentIndex(2)
		}
		raise(mtw.Handle())
	}

	return mtw.FormBase.WndProc(hwnd, msg, wParam, lParam)
}
