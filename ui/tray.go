/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"sort"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/l18n"
	"golang.zx2c4.com/wireguard/windows/manager"

	"github.com/lxn/walk"
)

// Status + active CIDRs + separator
const trayTunnelActionsOffset = 3

type Tray struct {
	*walk.NotifyIcon

	// Current known tunnels by name
	tunnels                  map[string]*walk.Action
	tunnelsAreInBreakoutMenu bool

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

func (tray *Tray) sortedTunnels() []string {
	var names []string
	for name := range tray.tunnels {
		names = append(names, name)
	}
	sort.SliceStable(names, func(i, j int) bool {
		return conf.TunnelNameIsLess(names[i], names[j])
	})
	return names
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
						showErrorCustom(tray.mtw, l18n.Sprintf("Failed to determine tunnel state"), err.Error())
					} else if oldState == manager.TunnelStopped {
						showErrorCustom(tray.mtw, l18n.Sprintf("Failed to activate tunnel"), err.Error())
					} else if oldState == manager.TunnelStarted {
						showErrorCustom(tray.mtw, l18n.Sprintf("Failed to deactivate tunnel"), err.Error())
					}
				})
			}
		}()
	})
	tray.tunnels[tunnel.Name] = tunnelAction

	var (
		idx  int
		name string
	)
	for idx, name = range tray.sortedTunnels() {
		if name == tunnel.Name {
			break
		}
	}

	if tray.tunnelsAreInBreakoutMenu {
		tray.ContextMenu().Actions().At(trayTunnelActionsOffset).Menu().Actions().Insert(idx, tunnelAction)
	} else {
		tray.ContextMenu().Actions().Insert(trayTunnelActionsOffset+idx, tunnelAction)
	}
	tray.rebalanceTunnelsMenu()

	go func() {
		state, err := tclosure.State()
		if err != nil {
			return
		}
		tray.mtw.Synchronize(func() {
			tray.setTunnelState(&tclosure, state)
		})
	}()
}

func (tray *Tray) removeTunnelAction(tunnelName string) {
	if tray.tunnelsAreInBreakoutMenu {
		tray.ContextMenu().Actions().At(trayTunnelActionsOffset).Menu().Actions().Remove(tray.tunnels[tunnelName])
	} else {
		tray.ContextMenu().Actions().Remove(tray.tunnels[tunnelName])
	}
	delete(tray.tunnels, tunnelName)
	tray.rebalanceTunnelsMenu()
}

func (tray *Tray) rebalanceTunnelsMenu() {
	if tray.tunnelsAreInBreakoutMenu && len(tray.tunnels) <= 10 {
		menuAction := tray.ContextMenu().Actions().At(trayTunnelActionsOffset)
		idx := 1
		for _, name := range tray.sortedTunnels() {
			tray.ContextMenu().Actions().Insert(trayTunnelActionsOffset+idx, tray.tunnels[name])
			idx++
		}
		tray.ContextMenu().Actions().Remove(menuAction)
		menuAction.Menu().Dispose()
		tray.tunnelsAreInBreakoutMenu = false
	} else if !tray.tunnelsAreInBreakoutMenu && len(tray.tunnels) > 10 {
		menu, err := walk.NewMenu()
		if err != nil {
			return
		}
		for _, name := range tray.sortedTunnels() {
			action := tray.tunnels[name]
			menu.Actions().Add(action)
			tray.ContextMenu().Actions().Remove(action)
		}
		menuAction, err := tray.ContextMenu().Actions().InsertMenu(trayTunnelActionsOffset, menu)
		if err != nil {
			return
		}
		menuAction.SetText(l18n.Sprintf("&Tunnels"))
		tray.tunnelsAreInBreakoutMenu = true
	}
}

func (tray *Tray) onTunnelChange(tunnel *manager.Tunnel, state manager.TunnelState, globalState manager.TunnelState, err error) {
	tray.mtw.Synchronize(func() {
		tray.updateGlobalState(globalState)
		if err == nil {
			tunnelAction := tray.tunnels[tunnel.Name]
			if tunnelAction != nil {
				wasChecked := tunnelAction.Checked()
				switch state {
				case manager.TunnelStarted:
					if !wasChecked {
						icon, _ := iconWithOverlayForState(state, 128)
						tray.ShowCustom(l18n.Sprintf("WireGuard Activated"), l18n.Sprintf("The %s tunnel has been activated.", tunnel.Name), icon)
					}

				case manager.TunnelStopped:
					if wasChecked {
						icon, _ := loadSystemIcon("imageres", -31, 128) // TODO: this icon isn't very good...
						tray.ShowCustom(l18n.Sprintf("WireGuard Deactivated"), l18n.Sprintf("The %s tunnel has been deactivated.", tunnel.Name), icon)
					}
				}
			}
		} else if !tray.mtw.Visible() {
			tray.ShowError(l18n.Sprintf("WireGuard Tunnel Error"), err.Error())
		}
		tray.setTunnelState(tunnel, state)
	})
}

func (tray *Tray) updateGlobalState(globalState manager.TunnelState) {
	if icon, err := iconWithOverlayForState(globalState, 16); err == nil {
		tray.SetIcon(icon)
	}

	actions := tray.ContextMenu().Actions()
	statusAction := actions.At(0)

	tray.SetToolTip(l18n.Sprintf("WireGuard: %s", textForState(globalState, true)))
	stateText := textForState(globalState, false)
	stateIcon, err := iconForState(globalState, 16)
	if err == nil {
		statusAction.SetImage(stateIcon)
	}
	statusAction.SetText(l18n.Sprintf("Status: %s", stateText))

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

	for _, action := range tray.tunnels {
		action.SetEnabled(globalState == manager.TunnelStarted || globalState == manager.TunnelStopped)
	}
}

func (tray *Tray) setTunnelState(tunnel *manager.Tunnel, state manager.TunnelState) {
	tunnelAction := tray.tunnels[tunnel.Name]
	if tunnelAction == nil {
		return
	}

	switch state {
	case manager.TunnelStarted:
		tunnelAction.SetEnabled(true)
		tunnelAction.SetChecked(true)

	case manager.TunnelStopped:
		tunnelAction.SetChecked(false)
	}
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
