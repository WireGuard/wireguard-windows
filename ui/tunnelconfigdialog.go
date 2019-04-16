/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"fmt"
	"strings"

	"github.com/lxn/walk"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/service"
	"golang.zx2c4.com/wireguard/windows/ui/syntax"
)

const (
	configKeyDNS        = "DNS"
	configKeyAllowedIPs = "AllowedIPs"
)

var (
	ipv4Wildcard       = orderedStringSetFromSlice([]string{"0.0.0.0/0"})
	ipv4PublicNetworks = orderedStringSetFromSlice([]string{
		"0.0.0.0/5", "8.0.0.0/7", "11.0.0.0/8", "12.0.0.0/6", "16.0.0.0/4", "32.0.0.0/3",
		"64.0.0.0/2", "128.0.0.0/3", "160.0.0.0/5", "168.0.0.0/6", "172.0.0.0/12",
		"172.32.0.0/11", "172.64.0.0/10", "172.128.0.0/9", "173.0.0.0/8", "174.0.0.0/7",
		"176.0.0.0/4", "192.0.0.0/9", "192.128.0.0/11", "192.160.0.0/13", "192.169.0.0/16",
		"192.170.0.0/15", "192.172.0.0/14", "192.176.0.0/12", "192.192.0.0/10",
		"193.0.0.0/8", "194.0.0.0/7", "196.0.0.0/6", "200.0.0.0/5", "208.0.0.0/4",
	})
)

type allowedIPsState int

const (
	allowedIPsStateInvalid allowedIPsState = iota
	allowedIPsStateContainsIPV4Wildcard
	allowedIPsStateContainsIPV4PublicNetworks
	allowedIPsStateOther
)

type TunnelConfigDialog struct {
	*walk.Dialog
	nameEdit            *walk.LineEdit
	pubkeyEdit          *walk.LineEdit
	syntaxEdit          *syntax.SyntaxEdit
	excludePrivateIPsCB *walk.CheckBox
	saveButton          *walk.PushButton
	tunnel              *service.Tunnel
	config              conf.Config
	allowedIPsState     allowedIPsState
	lastPrivateKey      string
	inCheckedChanged    bool
}

func runTunnelConfigDialog(owner walk.Form, tunnel *service.Tunnel) *conf.Config {
	var (
		title string
		name  string
	)

	dlg := &TunnelConfigDialog{tunnel: tunnel}

	if tunnel == nil {
		// Creating a new tunnel, create a new private key and use the default template
		title = "Create new tunnel"
		pk, _ := conf.NewPrivateKey()
		dlg.config = conf.Config{Interface: conf.Interface{PrivateKey: *pk}}
	} else {
		title = "Edit tunnel"
		name = tunnel.Name
		dlg.config, _ = tunnel.StoredConfig()
	}

	layout := walk.NewGridLayout()
	layout.SetSpacing(6)
	layout.SetMargins(walk.Margins{18, 18, 18, 18})
	layout.SetColumnStretchFactor(1, 3)

	dlg.Dialog, _ = walk.NewDialog(owner)
	dlg.SetIcon(owner.Icon())
	dlg.SetTitle(title)
	dlg.SetLayout(layout)
	dlg.SetMinMaxSize(walk.Size{500, 400}, walk.Size{9999, 9999})

	nameLabel, _ := walk.NewTextLabel(dlg)
	layout.SetRange(nameLabel, walk.Rectangle{0, 0, 1, 1})
	nameLabel.SetTextAlignment(walk.AlignHFarVCenter)
	nameLabel.SetText("Name:")

	dlg.nameEdit, _ = walk.NewLineEdit(dlg)
	layout.SetRange(dlg.nameEdit, walk.Rectangle{1, 0, 1, 1})
	dlg.nameEdit.SetText(name)

	pubkeyLabel, _ := walk.NewTextLabel(dlg)
	layout.SetRange(pubkeyLabel, walk.Rectangle{0, 1, 1, 1})
	pubkeyLabel.SetTextAlignment(walk.AlignHFarVCenter)
	pubkeyLabel.SetText("Public key:")

	dlg.pubkeyEdit, _ = walk.NewLineEdit(dlg)
	layout.SetRange(dlg.pubkeyEdit, walk.Rectangle{1, 1, 1, 1})
	dlg.pubkeyEdit.SetReadOnly(true)
	dlg.pubkeyEdit.SetText("(unknown)")

	dlg.syntaxEdit, _ = syntax.NewSyntaxEdit(dlg)
	layout.SetRange(dlg.syntaxEdit, walk.Rectangle{0, 2, 2, 1})
	dlg.syntaxEdit.SetText(dlg.config.ToWgQuick())
	dlg.syntaxEdit.PrivateKeyChanged().Attach(dlg.onSyntaxEditPrivateKeyChanged)
	dlg.syntaxEdit.TextChanged().Attach(dlg.updateExcludePrivateIPsCBVisible)

	buttonsContainer, _ := walk.NewComposite(dlg)
	layout.SetRange(buttonsContainer, walk.Rectangle{0, 3, 2, 1})
	buttonsContainer.SetLayout(walk.NewHBoxLayout())
	buttonsContainer.Layout().SetMargins(walk.Margins{})

	dlg.excludePrivateIPsCB, _ = walk.NewCheckBox(buttonsContainer)
	dlg.excludePrivateIPsCB.SetText("Exclude private IPs")
	dlg.excludePrivateIPsCB.CheckedChanged().Attach(dlg.onExcludePrivateIPsCBCheckedChanged)
	dlg.updateExcludePrivateIPsCBVisible()

	walk.NewHSpacer(buttonsContainer)

	dlg.saveButton, _ = walk.NewPushButton(buttonsContainer)
	dlg.saveButton.SetText("Save")
	dlg.saveButton.Clicked().Attach(dlg.onSaveButtonClicked)

	cancelButton, _ := walk.NewPushButton(buttonsContainer)
	cancelButton.SetText("Cancel")
	cancelButton.Clicked().Attach(dlg.Cancel)

	dlg.SetCancelButton(cancelButton)
	dlg.SetDefaultButton(dlg.saveButton)

	dlg.updateAllowedIPsState()

	if dlg.Run() == walk.DlgCmdOK {
		// Save
		return &dlg.config
	}

	return nil
}

func (dlg *TunnelConfigDialog) updateAllowedIPsState() {
	var newState allowedIPsState
	if len(dlg.config.Peers) == 1 {
		if allowedIPs := dlg.allowedIPsSet(); allowedIPs.IsSupersetOf(ipv4Wildcard) {
			newState = allowedIPsStateContainsIPV4Wildcard
		} else if allowedIPs.IsSupersetOf(ipv4PublicNetworks) {
			newState = allowedIPsStateContainsIPV4PublicNetworks
		} else {
			newState = allowedIPsStateOther
		}
	} else {
		newState = allowedIPsStateInvalid
	}

	if newState != dlg.allowedIPsState {
		dlg.allowedIPsState = newState

		dlg.excludePrivateIPsCB.SetVisible(dlg.canExcludePrivateIPs())
		dlg.excludePrivateIPsCB.SetChecked(dlg.privateIPsExcluded())
	}
}

func (dlg *TunnelConfigDialog) canExcludePrivateIPs() bool {
	return dlg.allowedIPsState == allowedIPsStateContainsIPV4PublicNetworks ||
		dlg.allowedIPsState == allowedIPsStateContainsIPV4Wildcard
}

func (dlg *TunnelConfigDialog) privateIPsExcluded() bool {
	return dlg.allowedIPsState == allowedIPsStateContainsIPV4PublicNetworks
}

func (dlg *TunnelConfigDialog) setPrivateIPsExcluded(excluded bool) {
	if !dlg.canExcludePrivateIPs() || dlg.privateIPsExcluded() == excluded {
		return
	}

	var oldNetworks, newNetworks *orderedStringSet
	if excluded {
		oldNetworks, newNetworks = ipv4Wildcard, ipv4PublicNetworks
	} else {
		oldNetworks, newNetworks = ipv4PublicNetworks, ipv4Wildcard
	}
	input := dlg.allowedIPs()
	output := newOrderedStringSet()
	var replaced bool

	// Replace the first instance of the wildcard with the public network list, or vice versa.
	for _, network := range input {
		if oldNetworks.Contains(network) {
			if !replaced {
				output.UniteWith(newNetworks)
				replaced = true
			}
		} else {
			output.Add(network)
		}
	}

	// DNS servers only need to be handled specially when we're excluding private IPs.
	for _, route := range dlg.dnsRoutes() {
		if excluded {
			output.Add(route)
		} else {
			output.Remove(route)
			output.Remove(route + "/32")
		}
	}

	if excluded {
		dlg.allowedIPsState = allowedIPsStateContainsIPV4PublicNetworks
	} else {
		dlg.allowedIPsState = allowedIPsStateContainsIPV4Wildcard
	}

	dlg.replaceLine(configKeyAllowedIPs, strings.Join(output.ToSlice(), ", "))
}

func (dlg *TunnelConfigDialog) replaceLine(key, value string) {
	text := dlg.syntaxEdit.Text()

	start := strings.Index(text, key)
	end := start + strings.Index(text[start:], "\n")
	oldLine := text[start:end]
	newLine := fmt.Sprintf("%s = %s", key, value)

	dlg.syntaxEdit.SetText(strings.ReplaceAll(text, oldLine, newLine))
}

func (dlg *TunnelConfigDialog) updateExcludePrivateIPsCBVisible() {
	dlg.updateAllowedIPsState()

	dlg.excludePrivateIPsCB.SetVisible(dlg.canExcludePrivateIPs())
}

func (dlg *TunnelConfigDialog) dnsRoutes() []string {
	return dlg.routes(configKeyDNS)
}

func (dlg *TunnelConfigDialog) allowedIPs() []string {
	return dlg.routes(configKeyAllowedIPs)
}

func (dlg *TunnelConfigDialog) allowedIPsSet() *orderedStringSet {
	return orderedStringSetFromSlice(dlg.allowedIPs())
}

func (dlg *TunnelConfigDialog) routes(key string) []string {
	var routes []string

	lines := strings.Split(dlg.syntaxEdit.Text(), "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), key) {
			routesMaybeWithSpace := strings.Split(strings.TrimSpace(line[strings.IndexByte(line, '=')+1:]), ",")
			routes = make([]string, len(routesMaybeWithSpace))
			for i, route := range routesMaybeWithSpace {
				routes[i] = strings.TrimSpace(route)
			}
			break
		}
	}

	return routes
}

func (dlg *TunnelConfigDialog) onExcludePrivateIPsCBCheckedChanged() {
	dlg.setPrivateIPsExcluded(dlg.excludePrivateIPsCB.Checked())
}

func (dlg *TunnelConfigDialog) onSyntaxEditPrivateKeyChanged(privateKey string) {
	if privateKey == dlg.lastPrivateKey {
		return
	}
	dlg.lastPrivateKey = privateKey
	key, _ := conf.NewPrivateKeyFromString(privateKey)
	if key != nil {
		dlg.pubkeyEdit.SetText(key.Public().String())
	} else {
		dlg.pubkeyEdit.SetText("(unknown)")
	}
}

func (dlg *TunnelConfigDialog) onSaveButtonClicked() {
	newName := dlg.nameEdit.Text()
	if newName == "" {
		walk.MsgBox(dlg, "Invalid configuration", "Name is required", walk.MsgBoxIconWarning)
		return
	}

	if dlg.tunnel != nil && dlg.tunnel.Name != newName {
		names, err := conf.ListConfigNames()
		if err != nil {
			walk.MsgBox(dlg, "Error", err.Error(), walk.MsgBoxIconError)
			return
		}

		for _, name := range names {
			if name == newName {
				walk.MsgBox(dlg, "Invalid configuration", fmt.Sprintf("Another tunnel already exists with the name ‘%s’.", newName), walk.MsgBoxIconWarning)
				return
			}
		}
	}

	if !conf.TunnelNameIsValid(newName) {
		walk.MsgBox(dlg, "Invalid configuration", fmt.Sprintf("Tunnel name ‘%s’ is invalid.", newName), walk.MsgBoxIconWarning)
		return
	}

	cfg, err := conf.FromWgQuick(dlg.syntaxEdit.Text(), newName)
	if err != nil {
		walk.MsgBox(dlg, "Error", err.Error(), walk.MsgBoxIconError)
		return
	}

	dlg.config = *cfg

	dlg.Accept()
}
