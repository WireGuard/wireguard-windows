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
	"golang.zx2c4.com/wireguard/windows/manager"
	"golang.zx2c4.com/wireguard/windows/ui/syntax"
)

type EditDialog struct {
	*walk.Dialog
	nameEdit                        *walk.LineEdit
	pubkeyEdit                      *walk.LineEdit
	syntaxEdit                      *syntax.SyntaxEdit
	blockUntunneledTrafficCB        *walk.CheckBox
	saveButton                      *walk.PushButton
	config                          conf.Config
	lastPrivateKey                  string
	blockUntunneledTraficCheckGuard bool
}

func runTunnelEditDialog(owner walk.Form, tunnel *manager.Tunnel) *conf.Config {
	dlg := &EditDialog{}

	var title string
	if tunnel == nil {
		title = "Create new tunnel"
	} else {
		title = "Edit tunnel"
	}

	if tunnel == nil {
		// Creating a new tunnel, create a new private key and use the default template
		pk, _ := conf.NewPrivateKey()
		dlg.config = conf.Config{Interface: conf.Interface{PrivateKey: *pk}}
	} else {
		dlg.config, _ = tunnel.StoredConfig()
	}

	layout := walk.NewGridLayout()
	layout.SetSpacing(6)
	layout.SetMargins(walk.Margins{10, 10, 10, 10})
	layout.SetColumnStretchFactor(1, 3)

	dlg.Dialog, _ = walk.NewDialog(owner)
	dlg.SetIcon(owner.Icon())
	dlg.SetTitle(title)
	dlg.SetLayout(layout)
	dlg.SetMinMaxSize(walk.Size{500, 400}, walk.Size{0, 0})
	if icon, err := loadSystemIcon("imageres", 109, 32); err == nil {
		dlg.SetIcon(icon)
	}

	nameLabel, _ := walk.NewTextLabel(dlg)
	layout.SetRange(nameLabel, walk.Rectangle{0, 0, 1, 1})
	nameLabel.SetTextAlignment(walk.AlignHFarVCenter)
	nameLabel.SetText("Name:")

	dlg.nameEdit, _ = walk.NewLineEdit(dlg)
	layout.SetRange(dlg.nameEdit, walk.Rectangle{1, 0, 1, 1})
	dlg.nameEdit.SetText(dlg.config.Name)

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

	buttonsContainer, _ := walk.NewComposite(dlg)
	layout.SetRange(buttonsContainer, walk.Rectangle{0, 3, 2, 1})
	buttonsContainer.SetLayout(walk.NewHBoxLayout())
	buttonsContainer.Layout().SetMargins(walk.Margins{})

	dlg.blockUntunneledTrafficCB, _ = walk.NewCheckBox(buttonsContainer)
	dlg.blockUntunneledTrafficCB.SetText("Block untunneled traffic (kill-switch)")
	dlg.blockUntunneledTrafficCB.SetToolTipText("When a configuration has exactly one peer, and that peer has an allowed IPs containing at least one of 0.0.0.0/0 or ::/0, then the tunnel service engages a firewall ruleset to block all traffic that is neither to nor from the tunnel interface, with special exceptions for DHCP and NDP.")
	dlg.blockUntunneledTrafficCB.SetVisible(false)
	dlg.blockUntunneledTrafficCB.CheckedChanged().Attach(dlg.onBlockUntunneledTrafficCBCheckedChanged)

	walk.NewHSpacer(buttonsContainer)

	dlg.saveButton, _ = walk.NewPushButton(buttonsContainer)
	dlg.saveButton.SetText("Save")
	dlg.saveButton.Clicked().Attach(dlg.onSaveButtonClicked)

	cancelButton, _ := walk.NewPushButton(buttonsContainer)
	cancelButton.SetText("Cancel")
	cancelButton.Clicked().Attach(dlg.Cancel)

	dlg.SetCancelButton(cancelButton)
	dlg.SetDefaultButton(dlg.saveButton)

	dlg.syntaxEdit.PrivateKeyChanged().Attach(dlg.onSyntaxEditPrivateKeyChanged)
	dlg.syntaxEdit.BlockUntunneledTrafficStateChanged().Attach(dlg.onBlockUntunneledTrafficStateChanged)
	dlg.syntaxEdit.SetText(dlg.config.ToWgQuick())

	if tunnel != nil {
		dlg.nameEdit.SetFocus() // TODO: This works around a walk issue with scrolling in weird ways <https://github.com/lxn/walk/issues/505>. We should fix this in walk instead of here.

		dlg.Starting().Attach(func() {
			dlg.syntaxEdit.SetFocus()
		})
	}

	if dlg.Run() == walk.DlgCmdOK {
		return &dlg.config
	}

	return nil
}

func (dlg *EditDialog) onBlockUntunneledTrafficCBCheckedChanged() {
	if dlg.blockUntunneledTraficCheckGuard {
		return
	}
	var (
		v40 = [4]byte{}
		v60 = [16]byte{}
		v48 = [4]byte{0x80}
		v68 = [16]byte{0x80}
	)

	block := dlg.blockUntunneledTrafficCB.Checked()
	cfg, err := conf.FromWgQuick(dlg.syntaxEdit.Text(), "temporary")
	var newAllowedIPs []conf.IPCidr

	if err != nil {
		goto err
	}
	if len(cfg.Peers) != 1 {
		goto err
	}

	newAllowedIPs = make([]conf.IPCidr, 0, len(cfg.Peers[0].AllowedIPs))
	if block {
		var (
			foundV401    bool
			foundV41281  bool
			foundV600001 bool
			foundV680001 bool
		)
		for _, allowedip := range cfg.Peers[0].AllowedIPs {
			if allowedip.Cidr == 1 && len(allowedip.IP) == 16 && allowedip.IP.Equal(v60[:]) {
				foundV600001 = true
			} else if allowedip.Cidr == 1 && len(allowedip.IP) == 16 && allowedip.IP.Equal(v68[:]) {
				foundV680001 = true
			} else if allowedip.Cidr == 1 && len(allowedip.IP) == 4 && allowedip.IP.Equal(v40[:]) {
				foundV401 = true
			} else if allowedip.Cidr == 1 && len(allowedip.IP) == 4 && allowedip.IP.Equal(v48[:]) {
				foundV41281 = true
			} else {
				newAllowedIPs = append(newAllowedIPs, allowedip)
			}
		}
		if !((foundV401 && foundV41281) || (foundV600001 && foundV680001)) {
			goto err
		}
		if foundV401 && foundV41281 {
			newAllowedIPs = append(newAllowedIPs, conf.IPCidr{v40[:], 0})
		} else if foundV401 {
			newAllowedIPs = append(newAllowedIPs, conf.IPCidr{v40[:], 1})
		} else if foundV41281 {
			newAllowedIPs = append(newAllowedIPs, conf.IPCidr{v48[:], 1})
		}
		if foundV600001 && foundV680001 {
			newAllowedIPs = append(newAllowedIPs, conf.IPCidr{v60[:], 0})
		} else if foundV600001 {
			newAllowedIPs = append(newAllowedIPs, conf.IPCidr{v60[:], 1})
		} else if foundV680001 {
			newAllowedIPs = append(newAllowedIPs, conf.IPCidr{v68[:], 1})
		}
		cfg.Peers[0].AllowedIPs = newAllowedIPs
	} else {
		var (
			foundV400 bool
			foundV600 bool
		)
		for _, allowedip := range cfg.Peers[0].AllowedIPs {
			if allowedip.Cidr == 0 && len(allowedip.IP) == 16 && allowedip.IP.Equal(v60[:]) {
				foundV600 = true
			} else if allowedip.Cidr == 0 && len(allowedip.IP) == 4 && allowedip.IP.Equal(v40[:]) {
				foundV400 = true
			} else {
				newAllowedIPs = append(newAllowedIPs, allowedip)
			}
		}
		if !(foundV400 || foundV600) {
			goto err
		}
		if foundV400 {
			newAllowedIPs = append(newAllowedIPs, conf.IPCidr{v40[:], 1})
			newAllowedIPs = append(newAllowedIPs, conf.IPCidr{v48[:], 1})
		}
		if foundV600 {
			newAllowedIPs = append(newAllowedIPs, conf.IPCidr{v60[:], 1})
			newAllowedIPs = append(newAllowedIPs, conf.IPCidr{v68[:], 1})
		}
		cfg.Peers[0].AllowedIPs = newAllowedIPs
	}
	dlg.syntaxEdit.SetText(cfg.ToWgQuick())
	return

err:
	walk.MsgBox(dlg, "Invalid configuration", "Unable to toggle untunneled traffic blocking state.", walk.MsgBoxIconWarning)
	dlg.blockUntunneledTrafficCB.SetVisible(false)
}

func (dlg *EditDialog) onBlockUntunneledTrafficStateChanged(state int) {
	dlg.blockUntunneledTraficCheckGuard = true
	switch state {
	case syntax.InevaluableBlockingUntunneledTraffic:
		dlg.blockUntunneledTrafficCB.SetVisible(false)
	case syntax.BlockingUntunneledTraffic:
		dlg.blockUntunneledTrafficCB.SetVisible(true)
		dlg.blockUntunneledTrafficCB.SetChecked(true)
	case syntax.NotBlockingUntunneledTraffic:
		dlg.blockUntunneledTrafficCB.SetVisible(true)
		dlg.blockUntunneledTrafficCB.SetChecked(false)
	}
	dlg.blockUntunneledTraficCheckGuard = false
}

func (dlg *EditDialog) onSyntaxEditPrivateKeyChanged(privateKey string) {
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

func (dlg *EditDialog) onSaveButtonClicked() {
	newName := dlg.nameEdit.Text()
	if newName == "" {
		walk.MsgBox(dlg, "Invalid name", "A name is required.", walk.MsgBoxIconWarning)
		return
	}
	if !conf.TunnelNameIsValid(newName) {
		walk.MsgBox(dlg, "Invalid name", fmt.Sprintf("Tunnel name ‘%s’ is invalid.", newName), walk.MsgBoxIconWarning)
		return
	}
	newNameLower := strings.ToLower(newName)

	if newNameLower != strings.ToLower(dlg.config.Name) {
		existingTunnelList, err := manager.IPCClientTunnels()
		if err != nil {
			walk.MsgBox(dlg, "Unable to list existing tunnels", err.Error(), walk.MsgBoxIconError)
			return
		}
		for _, tunnel := range existingTunnelList {
			if strings.ToLower(tunnel.Name) == newNameLower {
				walk.MsgBox(dlg, "Tunnel already exists", fmt.Sprintf("Another tunnel already exists with the name ‘%s’.", newName), walk.MsgBoxIconWarning)
				return
			}
		}
	}

	cfg, err := conf.FromWgQuick(dlg.syntaxEdit.Text(), newName)
	if err != nil {
		walk.MsgBox(dlg, "Unable to create new configuration", err.Error(), walk.MsgBoxIconError)
		return
	}

	dlg.config = *cfg
	dlg.Accept()
}
