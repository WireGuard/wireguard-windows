/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/lxn/walk"
	"golang.zx2c4.com/wireguard/windows/service"
)

// Status + active CIDRs + separator
const trayTunnelActionsOffset = 3

type Tray struct {
	*walk.NotifyIcon

	// Current known tunnels by name
	tunnels map[string]*walk.Action

	mtw *ManageTunnelsWindow

	tunnelChangedCB  *service.TunnelChangeCallback
	tunnelsChangedCB *service.TunnelsChangeCallback
}

func NewTray(mtw *ManageTunnelsWindow) (*Tray, error) {
	var err error

	tray := &Tray{
		mtw:     mtw,
		tunnels: make(map[string]*walk.Action),
	}

	tray.NotifyIcon, err = walk.NewNotifyIcon(mtw.MainWindow)
	if err != nil {
		return nil, err
	}

	return tray, tray.setup()
}

func (tray *Tray) setup() error {
	tray.SetToolTip("WireGuard: Deactivated")
	tray.SetVisible(true)
	tray.SetIcon(iconProvider.wireguardIcon)

	tray.MouseDown().Attach(func(x, y int, button walk.MouseButton) {
		if button == walk.LeftButton {
			tray.onManageTunnels()
		}
	})

	// configure initial menu items
	for _, item := range [...]struct {
		label     string
		handler   walk.EventHandler
		enabled   bool
		hidden    bool
		separator bool
		defawlt   bool
	}{
		{label: "Status: Unknown"},
		{label: "Networks: None", hidden: true},
		{separator: true},
		{separator: true},
		{label: "&Manage tunnels...", handler: tray.onManageTunnels, enabled: true, defawlt: true},
		{label: "&Import tunnel(s) from file...", handler: tray.mtw.tunnelsPage.onImport, enabled: true},
		{separator: true},
		{label: "&About WireGuard", handler: func() { onAbout(tray.mtw) }, enabled: true},
		{label: "&Exit", handler: onQuit, enabled: true},
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
	tray.tunnelChangedCB = service.IPCClientRegisterTunnelChange(tray.onTunnelChange)
	tray.tunnelsChangedCB = service.IPCClientRegisterTunnelsChange(tray.onTunnelsChange)
	tray.onTunnelsChange()
	globalState, _ := service.IPCClientGlobalState()
	tray.updateGlobalState(globalState)

	return nil
}

func (tray *Tray) Dispose() error {
	if tray.tunnelChangedCB != nil {
		tray.tunnelChangedCB.Unregister()
		tray.tunnelChangedCB = nil
	}
	if tray.tunnelsChangedCB != nil {
		tray.tunnelsChangedCB.Unregister()
		tray.tunnelsChangedCB = nil
	}
	return tray.NotifyIcon.Dispose()
}

func (tray *Tray) onTunnelsChange() {
	tunnels, err := service.IPCClientTunnels()
	if err != nil {
		return
	}
	tray.mtw.Synchronize(func() {
		tunnelSet := make(map[string]bool, len(tunnels))
		for _, tunnel := range tunnels {
			tunnelSet[tunnel.Name] = true
			if tray.tunnels[tunnel.Name] == nil {
				tray.addTunnelAction(&tunnel)
			}
		}
		for trayTunnel := range tray.tunnels {
			if !tunnelSet[trayTunnel] {
				tray.removeTunnelAction(trayTunnel)
			}
		}
	})
}

func (tray *Tray) addTunnelAction(tunnel *service.Tunnel) {
	tunnelAction := walk.NewAction()
	tunnelAction.SetText(tunnel.Name)
	tunnelAction.SetEnabled(true)
	tunnelAction.SetCheckable(true)
	tclosure := *tunnel
	tunnelAction.Triggered().Attach(func() {
		tunnelAction.SetChecked(!tunnelAction.Checked())
		go func() {
			oldState, err := tclosure.Toggle()
			if err != nil {
				tray.mtw.Synchronize(func() {
					tray.mtw.Show()
					tray.mtw.tunnelsPage.listView.selectTunnel(tclosure.Name)
					tray.mtw.tabs.SetCurrentIndex(0)
					if oldState == service.TunnelUnknown {
						walk.MsgBox(tray.mtw, "Failed to determine tunnel state", err.Error(), walk.MsgBoxIconError)
					} else if oldState == service.TunnelStopped {
						walk.MsgBox(tray.mtw, "Failed to activate tunnel", err.Error(), walk.MsgBoxIconError)
					} else if oldState == service.TunnelStarted {
						walk.MsgBox(tray.mtw, "Failed to deactivate tunnel", err.Error(), walk.MsgBoxIconError)
					}
				})
			}
		}()
	})
	tray.tunnels[tunnel.Name] = tunnelAction

	// Add the action at the right spot
	var names []string
	for name := range tray.tunnels {
		names = append(names, name)
	}
	sort.Strings(names) //TODO: use correct sorting order for this

	var (
		idx  int
		name string
	)
	for idx, name = range names {
		if name == tunnel.Name {
			break
		}
	}

	tray.ContextMenu().Actions().Insert(trayTunnelActionsOffset+idx, tunnelAction)

	go func() {
		state, err := tunnel.State()
		if err != nil {
			return
		}
		tray.mtw.Synchronize(func() {
			tray.SetTunnelState(tunnel, state, false)
		})
	}()
}

func (tray *Tray) removeTunnelAction(tunnelName string) {
	tray.ContextMenu().Actions().Remove(tray.tunnels[tunnelName])
	delete(tray.tunnels, tunnelName)
}

func (tray *Tray) onTunnelChange(tunnel *service.Tunnel, state service.TunnelState, globalState service.TunnelState, err error) {
	tray.mtw.Synchronize(func() {
		tray.SetTunnelState(tunnel, state, err == nil)
		tray.updateGlobalState(globalState)
		if !tray.mtw.Visible() && err != nil {
			tray.ShowError("WireGuard Tunnel Error", err.Error())
		}
	})
}

func (tray *Tray) updateGlobalState(globalState service.TunnelState) {
	if icon, err := iconProvider.IconWithOverlayForState(globalState); err == nil {
		tray.SetIcon(icon)
	}

	actions := tray.ContextMenu().Actions()
	statusAction := actions.At(0)
	activeCIDRsAction := actions.At(1)

	setTunnelActionsEnabled := func(enabled bool) {
		for i := 0; i < len(tray.tunnels); i++ {
			action := actions.At(trayTunnelActionsOffset + i)
			action.SetEnabled(enabled)
		}
	}

	switch globalState {
	case service.TunnelStarting:
		statusAction.SetText("Status: Activating")
		setTunnelActionsEnabled(false)
		tray.SetToolTip("WireGuard: Activating...")

	case service.TunnelStarted:
		activeCIDRsAction.SetVisible(true)
		statusAction.SetText("Status: Active")
		setTunnelActionsEnabled(true)
		tray.SetToolTip("WireGuard: Activated")

	case service.TunnelStopping:
		statusAction.SetText("Status: Deactivating")
		setTunnelActionsEnabled(false)
		tray.SetToolTip("WireGuard: Deactivating...")

	case service.TunnelStopped:
		activeCIDRsAction.SetVisible(false)
		statusAction.SetText("Status: Inactive")
		setTunnelActionsEnabled(true)
		tray.SetToolTip("WireGuard: Deactivated")
	}
}

func (tray *Tray) SetTunnelState(tunnel *service.Tunnel, state service.TunnelState, showNotifications bool) {
	tunnelAction := tray.tunnels[tunnel.Name]

	actions := tray.ContextMenu().Actions()
	activeCIDRsAction := actions.At(1)

	wasChecked := tunnelAction.Checked()

	switch state {
	case service.TunnelStarted:
		activeCIDRsAction.SetText("")
		go func() {
			config, err := tunnel.RuntimeConfig()
			if err == nil {
				var sb strings.Builder
				for i, addr := range config.Interface.Addresses {
					if i > 0 {
						sb.WriteString(", ")
					}

					sb.WriteString(addr.String())
				}
				tray.mtw.Synchronize(func() {
					activeCIDRsAction.SetText(fmt.Sprintf("Networks: %s", sb.String()))
				})
			}
		}()
		tunnelAction.SetEnabled(true)
		tunnelAction.SetChecked(true)
		if !wasChecked && showNotifications {
			tray.ShowInfo("WireGuard Activated", fmt.Sprintf("The %s tunnel has been activated.", tunnel.Name))
		}

	case service.TunnelStopped:
		tunnelAction.SetChecked(false)
		if wasChecked && showNotifications {
			tray.ShowInfo("WireGuard Deactivated", fmt.Sprintf("The %s tunnel has been deactivated.", tunnel.Name))
		}
	}
}

func (tray *Tray) UpdateFound() {
	action := walk.NewAction()
	action.SetText("An Update is Available!")
	if icon, err := iconProvider.UpdateAvailableImage(); err == nil {
		action.SetImage(icon)
	}
	action.Triggered().Attach(func() {
		tray.mtw.Show()
		tray.mtw.tabs.SetCurrentIndex(2)
	})
	tray.ContextMenu().Actions().Insert(tray.ContextMenu().Actions().Len()-2, action)
	tray.ShowWarning("WireGuard Update Available", "An update to WireGuard is now available. You are advised to update as soon as possible.")
}

func (tray *Tray) onManageTunnels() {
	if !tray.mtw.Visible() {
		tray.mtw.tunnelsPage.listView.SelectFirstActiveTunnel()
		tray.mtw.tabs.SetCurrentIndex(0)
	}
	tray.mtw.Show()
}
