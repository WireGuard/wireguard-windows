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

// Status + active CIDRs + deactivate + separator
const trayTunnelActionsOffset = 4

type Tray struct {
	*walk.NotifyIcon

	// Current known tunnels by name
	tunnels map[string]*walk.Action

	mtw  *ManageTunnelsWindow
	icon *walk.Icon
}

func NewTray(mtw *ManageTunnelsWindow, icon *walk.Icon) (*Tray, error) {
	var err error

	tray := &Tray{
		mtw:     mtw,
		icon:    icon,
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
	tray.SetIcon(tray.icon)

	tray.MouseDown().Attach(func(x, y int, button walk.MouseButton) {
		if button == walk.LeftButton {
			tray.mtw.Show()
		}
	})

	// configure initial menu items
	for _, item := range [...]struct {
		label     string
		handler   walk.EventHandler
		enabled   bool
		hidden    bool
		separator bool
	}{
		{label: "Status: Unknown"},
		{label: "Networks: None", hidden: true},
		{label: "Deactivate", handler: tray.onDeactivateTunnel, enabled: true, hidden: true},
		{separator: true},
		{separator: true},
		{label: "&Manage tunnels...", handler: tray.mtw.Show, enabled: true},
		{label: "&Import tunnel(s) from file...", handler: tray.mtw.onImport, enabled: true},
		{separator: true},
		{label: "&About WireGuard", handler: func() { onAbout(tray.mtw) }, enabled: true},
		{label: "&Quit", handler: onQuit, enabled: true},
	} {
		var action *walk.Action
		if item.separator {
			action = walk.NewSeparatorAction()
		} else {
			action = walk.NewAction()
			action.SetText(item.label)
			action.SetEnabled(item.enabled)
			action.SetVisible(!item.hidden)
			if item.handler != nil {
				action.Triggered().Attach(item.handler)
			}
		}

		tray.ContextMenu().Actions().Add(action)
	}

	tunnels, err := service.IPCClientTunnels()
	if err != nil {
		return err
	}

	for _, tunnel := range tunnels {
		tray.addTunnelAction(tunnel.Name)
	}

	tray.mtw.TunnelAdded().Attach(tray.addTunnelAction)
	tray.mtw.TunnelDeleted().Attach(tray.removeTunnelAction)

	return nil
}

func (tray *Tray) addTunnelAction(tunnelName string) {
	tunnelAction := walk.NewAction()
	tunnelAction.SetText(tunnelName)
	tunnelAction.SetEnabled(true)
	tunnelAction.SetCheckable(true)
	tunnelAction.Triggered().Attach(func() {
		if activeTunnel := tray.mtw.tunnelTracker.activeTunnel; activeTunnel != nil && activeTunnel.Name == tunnelName {
			tray.onDeactivateTunnel()
		} else {
			tray.onActivateTunnel(tunnelName)
		}
	})
	tray.tunnels[tunnelName] = tunnelAction

	// Add the action at the right spot
	var names []string
	for name, _ := range tray.tunnels {
		names = append(names, name)
	}
	sort.Strings(names)

	var (
		idx  int
		name string
	)
	for idx, name = range names {
		if name == tunnelName {
			break
		}
	}

	tray.ContextMenu().Actions().Insert(trayTunnelActionsOffset+idx, tunnelAction)
}

func (tray *Tray) removeTunnelAction(tunnelName string) {
	tray.ContextMenu().Actions().Remove(tray.tunnels[tunnelName])
	delete(tray.tunnels, tunnelName)
}

func (tray *Tray) SetTunnelState(tunnel *service.Tunnel, state service.TunnelState) {
	tray.SetTunnelStateWithNotification(tunnel, state, true)
}

func (tray *Tray) SetTunnelStateWithNotification(tunnel *service.Tunnel, state service.TunnelState, showNotifications bool) {
	if icon, err := tray.mtw.tunnelsView.imageProvider.IconWithOverlayForState(tray.icon, state); err == nil {
		tray.SetIcon(icon)
	}

	tunnelAction := tray.tunnels[tunnel.Name]

	actions := tray.ContextMenu().Actions()
	statusAction := actions.At(0)
	activeCIDRsAction := actions.At(1)
	deactivateAction := actions.At(2)

	setTunnelActionsEnabled := func(enabled bool) {
		for i := 0; i < len(tray.tunnels); i++ {
			action := actions.At(trayTunnelActionsOffset + i)
			action.SetEnabled(enabled)
		}
	}

	switch state {
	case service.TunnelStarting:
		statusAction.SetText("Status: Activating")
		setTunnelActionsEnabled(false)

		tray.SetToolTip("WireGuard: Activating...")

	case service.TunnelStarted:
		statusAction.SetText("Status: Active")
		setTunnelActionsEnabled(true)

		config, err := tunnel.RuntimeConfig()
		activeCIDRsAction.SetVisible(err == nil)
		deactivateAction.SetVisible(err == nil)
		if err == nil {
			var sb strings.Builder
			for i, addr := range config.Interface.Addresses {
				if i > 0 {
					sb.WriteString(", ")
				}

				sb.WriteString(addr.String())
			}

			activeCIDRsAction.SetText(fmt.Sprintf("Networks: %s", sb.String()))
		}

		tunnelAction.SetEnabled(true)
		tunnelAction.SetChecked(true)

		tray.SetToolTip("WireGuard: Activated")
		if showNotifications {
			tray.ShowInfo("WireGuard Activated", fmt.Sprintf("The %s tunnel has been activated.", tunnel.Name))
		}

	case service.TunnelStopping:
		statusAction.SetText("Status: Deactivating")
		setTunnelActionsEnabled(false)

		tray.SetToolTip("WireGuard: Deactivating...")

	case service.TunnelStopped:
		statusAction.SetText("Status: Inactive")
		activeCIDRsAction.SetVisible(false)
		deactivateAction.SetVisible(false)
		setTunnelActionsEnabled(true)
		tunnelAction.SetChecked(false)

		tray.SetToolTip("WireGuard: Deactivated")
		if showNotifications {
			tray.ShowInfo("WireGuard Deactivated", fmt.Sprintf("The %s tunnel has been deactivated.", tunnel.Name))
		}
	}
}

func (tray *Tray) onActivateTunnel(tunnelName string) {
	if err := tray.mtw.TunnelTracker().ActivateTunnel(&service.Tunnel{tunnelName}); err != nil {
		walk.MsgBox(tray.mtw, "Failed to activate tunnel", err.Error(), walk.MsgBoxIconError)
	}
}

func (tray *Tray) onDeactivateTunnel() {
	if err := tray.mtw.TunnelTracker().DeactivateTunnel(); err != nil {
		walk.MsgBox(tray.mtw, "Failed to deactivate tunnel", err.Error(), walk.MsgBoxIconError)
	}
}
