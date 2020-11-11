/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/windows/l18n"
	"golang.zx2c4.com/wireguard/windows/manager"

	"github.com/lxn/walk"
)

type Tray struct {
	*walk.NotifyIcon
	mtw             *ManageTunnelsWindow
	tunnelChangedCB *manager.TunnelChangeCallback
	clicked         func()
}

func NewTray(mtw *ManageTunnelsWindow) (*Tray, error) {
	var err error

	tray := &Tray{mtw: mtw}

	tray.NotifyIcon, err = walk.NewNotifyIcon(mtw)
	if err != nil {
		return nil, err
	}

	return tray, tray.setup()
}

func (tray *Tray) setup() error {
	tray.clicked = tray.onManageTunnels

	tray.SetToolTip(l18n.Sprintf("WireGuard: Deactivated"))
	tray.SetVisible(true)
	if icon, err := loadLogoIcon(16); err == nil {
		tray.SetIcon(icon)
	}

	tray.MouseDown().Attach(func(x, y int, button walk.MouseButton) {
		if button == walk.LeftButton {
			tray.clicked()
		}
	})
	tray.MessageClicked().Attach(func() {
		tray.clicked()
	})

	for _, item := range [...]struct {
		label     string
		handler   walk.EventHandler
		enabled   bool
		hidden    bool
		separator bool
		defawlt   bool
	}{
		{label: l18n.Sprintf("Status: Unknown")},
		{label: l18n.Sprintf("Addresses: None"), hidden: true},
		{label: l18n.Sprintf("&Deactivate"), handler: tray.onDeactivateTunnel, enabled: true, hidden: true},
		{separator: true},
		{separator: true},
		{label: l18n.Sprintf("&Manage tunnels…"), handler: tray.onManageTunnels, enabled: true, defawlt: true},
		{label: l18n.Sprintf("&Import tunnel(s) from file…"), handler: tray.onImport, enabled: true},
		{separator: true},
		{label: l18n.Sprintf("&About WireGuard…"), handler: tray.onAbout, enabled: true},
		{label: l18n.Sprintf("E&xit"), handler: onQuit, enabled: true},
	} {
		var action *walk.Action
		if item.separator {
			action = walk.NewSeparatorAction()
		} else {
			action = walk.NewAction()
			action.SetText(item.label)
			action.SetEnabled(item.enabled)
			action.SetVisible(!item.hidden)
			action.SetDefault(item.defawlt)
			if item.handler != nil {
				action.Triggered().Attach(item.handler)
			}
		}

		tray.ContextMenu().Actions().Add(action)
	}
	tray.tunnelChangedCB = manager.IPCClientRegisterTunnelChange(tray.onTunnelChange)
	globalState, _ := manager.IPCClientGlobalState()
	tray.updateGlobalState(globalState)

	return nil
}

func (tray *Tray) Dispose() error {
	if tray.tunnelChangedCB != nil {
		tray.tunnelChangedCB.Unregister()
		tray.tunnelChangedCB = nil
	}
	return tray.NotifyIcon.Dispose()
}

func (tray *Tray) onTunnelChange(tunnel *manager.Tunnel, state manager.TunnelState, globalState manager.TunnelState, err error) {
	tray.mtw.Synchronize(func() {
		tray.updateGlobalState(globalState)
		if err == nil {
			switch state {
			case manager.TunnelStarted:
				icon, _ := iconWithOverlayForState(state, 128)
				tray.ShowCustom(l18n.Sprintf("WireGuard Activated"), l18n.Sprintf("The %s tunnel has been activated.", tunnel.Name), icon)

			case manager.TunnelStopped:
				icon, _ := loadSystemIcon("imageres", -31, 128) // TODO: this icon isn't very good...
				tray.ShowCustom(l18n.Sprintf("WireGuard Deactivated"), l18n.Sprintf("The %s tunnel has been deactivated.", tunnel.Name), icon)
			}
		} else if !tray.mtw.Visible() {
			tray.ShowError(l18n.Sprintf("WireGuard Tunnel Error"), err.Error())
		}
	})
}

func (tray *Tray) updateGlobalState(globalState manager.TunnelState) {
	if icon, err := iconWithOverlayForState(globalState, 16); err == nil {
		tray.SetIcon(icon)
	}

	actions := tray.ContextMenu().Actions()
	statusAction := actions.At(0)
	deactivateTunnelAction := actions.At(2)

	tray.SetToolTip(l18n.Sprintf("WireGuard: %s", textForState(globalState, true)))
	stateText := textForState(globalState, false)
	statusAction.SetText(l18n.Sprintf("Status: %s", stateText))
	deactivateTunnelAction.SetVisible(globalState == manager.TunnelStarted)
	go func() {
		var addrs []string
		tunnels, err := manager.IPCClientTunnels()
		if err == nil {
			for i := range tunnels {
				state, err := tunnels[i].State()
				if err == nil && state == manager.TunnelStarted {
					config, err := tunnels[i].RuntimeConfig()
					if err == nil {
						for _, addr := range config.Interface.Addresses {
							addrs = append(addrs, addr.String())
						}
					}
				}
			}
		}
		tray.mtw.Synchronize(func() {
			activeCIDRsAction := tray.ContextMenu().Actions().At(1)
			activeCIDRsAction.SetText(l18n.Sprintf("Addresses: %s", strings.Join(addrs, l18n.EnumerationSeparator())))
			activeCIDRsAction.SetVisible(len(addrs) > 0)
		})
	}()
}

func (tray *Tray) UpdateFound() {
	action := walk.NewAction()
	action.SetText(l18n.Sprintf("An Update is Available!"))
	menuIcon, _ := loadSystemIcon("imageres", 1, 16)
	action.SetImage(menuIcon)
	action.SetDefault(true)
	showUpdateTab := func() {
		if !tray.mtw.Visible() {
			tray.mtw.tunnelsPage.listView.SelectFirstActiveTunnel()
		}
		tray.mtw.tabs.SetCurrentIndex(2)
		raise(tray.mtw.Handle())
	}
	action.Triggered().Attach(showUpdateTab)
	tray.clicked = showUpdateTab
	tray.ContextMenu().Actions().Insert(tray.ContextMenu().Actions().Len()-2, action)

	showUpdateBalloon := func() {
		icon, _ := loadSystemIcon("imageres", 1, 128)
		tray.ShowCustom(l18n.Sprintf("WireGuard Update Available"), l18n.Sprintf("An update to WireGuard is now available. You are advised to update as soon as possible."), icon)
	}

	timeSinceStart := time.Now().Sub(startTime)
	if timeSinceStart < time.Second*3 {
		time.AfterFunc(time.Second*3-timeSinceStart, func() {
			tray.mtw.Synchronize(showUpdateBalloon)
		})
	} else {
		showUpdateBalloon()
	}
}

func (tray *Tray) onDeactivateTunnel() {
	go func() {
		tunnels, err := manager.IPCClientTunnels()
		if err == nil {
			for i := range tunnels {
				state, err := tunnels[i].State()
				if err == nil && state != manager.TunnelStopped {
					err = tunnels[i].Stop()
				}
			}
		}
		if err != nil {
			tray.mtw.Synchronize(func() {
				showErrorCustom(tray.mtw, l18n.Sprintf("Failed to deactivate tunnel"), err.Error())
			})
		}
	}()
}

func (tray *Tray) onManageTunnels() {
	tray.mtw.tunnelsPage.listView.SelectFirstActiveTunnel()
	tray.mtw.tabs.SetCurrentIndex(0)
	raise(tray.mtw.Handle())
}

func (tray *Tray) onAbout() {
	if tray.mtw.Visible() {
		onAbout(tray.mtw)
	} else {
		onAbout(nil)
	}
}

func (tray *Tray) onImport() {
	raise(tray.mtw.Handle())
	tray.mtw.tunnelsPage.onImport()
}
