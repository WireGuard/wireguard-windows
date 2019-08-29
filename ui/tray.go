/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/manager"

	"github.com/lxn/walk"
)

// Status + active CIDRs + separator
const trayTunnelActionsOffset = 3

type Tray struct {
	*walk.NotifyIcon

	// Current known tunnels by name
	tunnels map[string]*walk.Action

	mtw *ManageTunnelsWindow

	tunnelChangedCB  *manager.TunnelChangeCallback
	tunnelsChangedCB *manager.TunnelsChangeCallback

	clicked func()
}

func NewTray(mtw *ManageTunnelsWindow) (*Tray, error) {
	var err error

	tray := &Tray{
		mtw:     mtw,
		tunnels: make(map[string]*walk.Action),
	}

	tray.NotifyIcon, err = walk.NewNotifyIcon(mtw)
	if err != nil {
		return nil, err
	}

	return tray, tray.setup()
}

func (tray *Tray) setup() error {
	tray.clicked = tray.onManageTunnels

	tray.SetToolTip("WireGuard: Deactivated")
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
		{label: "Status: Unknown"},
		{label: "Addresses: None", hidden: true},
		{separator: true},
		{separator: true},
		{label: "&Manage tunnels...", handler: tray.onManageTunnels, enabled: true, defawlt: true},
		{label: "&Import tunnel(s) from file...", handler: tray.onImport, enabled: true},
		{separator: true},
		{label: "&About WireGuard...", handler: tray.onAbout, enabled: true},
		{label: "E&xit", handler: onQuit, enabled: true},
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
	tray.tunnelsChangedCB = manager.IPCClientRegisterTunnelsChange(tray.onTunnelsChange)
	tray.onTunnelsChange()
	globalState, _ := manager.IPCClientGlobalState()
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
	tunnels, err := manager.IPCClientTunnels()
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

func (tray *Tray) addTunnelAction(tunnel *manager.Tunnel) {
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
					raise(tray.mtw.Handle())
					tray.mtw.tunnelsPage.listView.selectTunnel(tclosure.Name)
					tray.mtw.tabs.SetCurrentIndex(0)
					if oldState == manager.TunnelUnknown {
						showErrorCustom(tray.mtw, "Failed to determine tunnel state", err.Error())
					} else if oldState == manager.TunnelStopped {
						showErrorCustom(tray.mtw, "Failed to activate tunnel", err.Error())
					} else if oldState == manager.TunnelStarted {
						showErrorCustom(tray.mtw, "Failed to deactivate tunnel", err.Error())
					}
				})
			}
		}()
	})
	tray.tunnels[tunnel.Name] = tunnelAction

	var names []string
	for name := range tray.tunnels {
		names = append(names, name)
	}
	sort.SliceStable(names, func(i, j int) bool {
		return conf.TunnelNameIsLess(names[i], names[j])
	})

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
		state, err := tclosure.State()
		if err != nil {
			return
		}
		tray.mtw.Synchronize(func() {
			tray.SetTunnelState(&tclosure, state, false)
		})
	}()
}

func (tray *Tray) removeTunnelAction(tunnelName string) {
	tray.ContextMenu().Actions().Remove(tray.tunnels[tunnelName])
	delete(tray.tunnels, tunnelName)
}

func (tray *Tray) onTunnelChange(tunnel *manager.Tunnel, state manager.TunnelState, globalState manager.TunnelState, err error) {
	tray.mtw.Synchronize(func() {
		tray.updateGlobalState(globalState)
		tray.SetTunnelState(tunnel, state, err == nil)
		if !tray.mtw.Visible() && err != nil {
			tray.ShowError("WireGuard Tunnel Error", err.Error())
		}
	})
}

func (tray *Tray) updateGlobalState(globalState manager.TunnelState) {
	if icon, err := iconWithOverlayForState(globalState, 16); err == nil {
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

	tray.SetToolTip(fmt.Sprintf("WireGuard: %s", textForState(globalState, true)))
	statusAction.SetText(fmt.Sprintf("Status: %s", textForState(globalState, false)))

	switch globalState {
	case manager.TunnelStarting:
		setTunnelActionsEnabled(false)

	case manager.TunnelStarted:
		activeCIDRsAction.SetVisible(true)
		setTunnelActionsEnabled(true)

	case manager.TunnelStopping:
		setTunnelActionsEnabled(false)

	case manager.TunnelStopped:
		activeCIDRsAction.SetVisible(false)
		setTunnelActionsEnabled(true)
	}
}

func (tray *Tray) SetTunnelState(tunnel *manager.Tunnel, state manager.TunnelState, showNotifications bool) {
	tunnelAction := tray.tunnels[tunnel.Name]
	if tunnelAction == nil {
		return
	}

	actions := tray.ContextMenu().Actions()
	activeCIDRsAction := actions.At(1)

	wasChecked := tunnelAction.Checked()

	switch state {
	case manager.TunnelStarted:
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
					activeCIDRsAction.SetText(fmt.Sprintf("Addresses: %s", sb.String()))
				})
			}
		}()
		tunnelAction.SetEnabled(true)
		tunnelAction.SetChecked(true)
		if !wasChecked && showNotifications {
			icon, _ := iconWithOverlayForState(state, 128)
			tray.ShowCustom("WireGuard Activated", fmt.Sprintf("The %s tunnel has been activated.", tunnel.Name), icon)
		}

	case manager.TunnelStopped:
		tunnelAction.SetChecked(false)
		if wasChecked && showNotifications {
			icon, _ := loadSystemIcon("imageres", 26, 128) // TODO: this icon isn't very good...
			tray.ShowCustom("WireGuard Deactivated", fmt.Sprintf("The %s tunnel has been deactivated.", tunnel.Name), icon)
		}
	}
}

func (tray *Tray) UpdateFound() {
	action := walk.NewAction()
	action.SetText("An Update is Available!")
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
		tray.ShowCustom("WireGuard Update Available", "An update to WireGuard is now available. You are advised to update as soon as possible.", icon)
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

func (tray *Tray) onManageTunnels() {
	if !tray.mtw.Visible() {
		tray.mtw.tunnelsPage.listView.SelectFirstActiveTunnel()
		tray.mtw.tabs.SetCurrentIndex(0)
	}
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
