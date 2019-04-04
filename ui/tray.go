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

type Tray struct {
	*walk.NotifyIcon

	// Current known tunnels by name
	tunnels map[string]*walk.Action

	parent *ManageTunnelsWindow
	icon   *walk.Icon
}

func NewTray(parent *ManageTunnelsWindow, icon *walk.Icon) (*Tray, error) {
	var err error

	tray := &Tray{
		parent:  parent,
		icon:    icon,
		tunnels: make(map[string]*walk.Action),
	}
	tray.NotifyIcon, err = walk.NewNotifyIcon(parent.MainWindow)
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
			tray.parent.Show()
		}
	})

	// configure initial menu items
	for _, item := range [...]struct {
		label     string
		handler   walk.EventHandler
		enabled   bool
		separator bool
	}{
		{label: "Status: Unknown"},
		{label: "Networks: None"},
		{separator: true},
		{separator: true},
		{label: "&Manage tunnels...", handler: tray.parent.Show, enabled: true},
		{label: "&Import tunnel(s) from file...", handler: tray.parent.onImport, enabled: true},
		{separator: true},
		{label: "&About WireGuard", handler: onAbout, enabled: true},
		{label: "&Quit", handler: onQuit, enabled: true},
	} {
		var action *walk.Action
		if item.separator {
			action = walk.NewSeparatorAction()
		} else {
			action = walk.NewAction()
			action.SetText(item.label)
			action.SetEnabled(item.enabled)
			if item.handler != nil {
				action.Triggered().Attach(item.handler)
			}
		}

		tray.ContextMenu().Actions().Add(action)
	}

	return nil
}

func (tray *Tray) SetTunnelState(tunnel *service.Tunnel, state service.TunnelState) {
	tray.SetTunnelStateWithNotification(tunnel, state, true)
}

func (tray *Tray) SetTunnelStateWithNotification(tunnel *service.Tunnel, state service.TunnelState, showNotifications bool) {
	tunnelAction, ok := tray.tunnels[tunnel.Name]
	if !ok {
		// First time seeing this tunnel, create a new action
		tunnelAction = walk.NewAction()
		tunnelAction.SetText(tunnel.Name)
		tunnelAction.SetEnabled(true)
		tunnelAction.SetCheckable(true)
		// TODO: Wire up the click event
		tray.tunnels[tunnel.Name] = tunnelAction

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
			if name == tunnel.Name {
				break
			}
		}

		// Status + active CIDRs + separator
		const offset = 3

		tray.ContextMenu().Actions().Insert(idx+offset, tunnelAction)
	}

	// TODO: No event for deleting a tunnel?

	actions := tray.ContextMenu().Actions()
	statusAction := actions.At(0)
	activeCIDRsAction := actions.At(1)

	switch state {
	case service.TunnelStarting:
		statusAction.SetText("Activating")
		tunnelAction.SetEnabled(false)

		tray.SetToolTip("WireGuard: Activating...")
	case service.TunnelStarted:
		statusAction.SetText("Active")

		config, err := tunnel.RuntimeConfig()
		activeCIDRsAction.SetVisible(err == nil)
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
		statusAction.SetText("Deactivating")
		tunnelAction.SetEnabled(false)

		tray.SetToolTip("WireGuard: Deactivating...")
	case service.TunnelStopped:
		statusAction.SetText("Inactive")
		activeCIDRsAction.SetVisible(false)
		tunnelAction.SetEnabled(true)
		tunnelAction.SetChecked(false)

		tray.SetToolTip("WireGuard: Deactivated")
		if showNotifications {
			tray.ShowInfo("WireGuard Deactivated", fmt.Sprintf("The %s tunnel has been deactivated.", tunnel.Name))
		}
	}
}
