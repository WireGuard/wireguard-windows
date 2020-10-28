/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"strings"

	"github.com/lxn/walk"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/l18n"
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

func runEditDialog(owner walk.Form, tunnel *manager.Tunnel) *conf.Config {
	dlg, err := newEditDialog(owner, tunnel)
	if showError(err, owner) {
		return nil
	}

	if dlg.Run() == walk.DlgCmdOK {
		return &dlg.config
	}

	return nil
}

func newEditDialog(owner walk.Form, tunnel *manager.Tunnel) (*EditDialog, error) {
	var err error
	var disposables walk.Disposables
	defer disposables.Treat()

	dlg := new(EditDialog)

	var title string
	if tunnel == nil {
		title = l18n.Sprintf("Create new tunnel")
	} else {
		title = l18n.Sprintf("Edit tunnel")
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

	if dlg.Dialog, err = walk.NewDialog(owner); err != nil {
		return nil, err
	}
	disposables.Add(dlg)
	dlg.SetIcon(owner.Icon())
	dlg.SetTitle(title)
	dlg.SetLayout(layout)
	dlg.SetMinMaxSize(walk.Size{500, 400}, walk.Size{0, 0})
	if icon, err := loadSystemIcon("imageres", 109, 32); err == nil {
		dlg.SetIcon(icon)
	}

	nameLabel, err := walk.NewTextLabel(dlg)
	if err != nil {
		return nil, err
	}
	layout.SetRange(nameLabel, walk.Rectangle{0, 0, 1, 1})
	nameLabel.SetTextAlignment(walk.AlignHFarVCenter)
	nameLabel.SetText(l18n.Sprintf("&Name:"))

	if dlg.nameEdit, err = walk.NewLineEdit(dlg); err != nil {
		return nil, err
	}
	layout.SetRange(dlg.nameEdit, walk.Rectangle{1, 0, 1, 1})
	dlg.nameEdit.SetText(dlg.config.Name)

	pubkeyLabel, err := walk.NewTextLabel(dlg)
	if err != nil {
		return nil, err
	}
	layout.SetRange(pubkeyLabel, walk.Rectangle{0, 1, 1, 1})
	pubkeyLabel.SetTextAlignment(walk.AlignHFarVCenter)
	pubkeyLabel.SetText(l18n.Sprintf("&Public key:"))

	if dlg.pubkeyEdit, err = walk.NewLineEdit(dlg); err != nil {
		return nil, err
	}
	layout.SetRange(dlg.pubkeyEdit, walk.Rectangle{1, 1, 1, 1})
	dlg.pubkeyEdit.SetReadOnly(true)
	dlg.pubkeyEdit.SetText(l18n.Sprintf("(unknown)"))
	dlg.pubkeyEdit.Accessibility().SetRole(walk.AccRoleStatictext)

	if dlg.syntaxEdit, err = syntax.NewSyntaxEdit(dlg); err != nil {
		return nil, err
	}
	layout.SetRange(dlg.syntaxEdit, walk.Rectangle{0, 2, 2, 1})

	buttonsContainer, err := walk.NewComposite(dlg)
	if err != nil {
		return nil, err
	}
	layout.SetRange(buttonsContainer, walk.Rectangle{0, 3, 2, 1})
	buttonsContainer.SetLayout(walk.NewHBoxLayout())
	buttonsContainer.Layout().SetMargins(walk.Margins{})

	if dlg.blockUntunneledTrafficCB, err = walk.NewCheckBox(buttonsContainer); err != nil {
		return nil, err
	}
	dlg.blockUntunneledTrafficCB.SetText(l18n.Sprintf("&Block untunneled traffic (kill-switch)"))
	dlg.blockUntunneledTrafficCB.SetToolTipText(l18n.Sprintf("When a configuration has exactly one peer, and that peer has an allowed IPs containing at least one of 0.0.0.0/0 or ::/0, then the tunnel service engages a firewall ruleset to block all traffic that is neither to nor from the tunnel interface, with special exceptions for DHCP and NDP."))
	dlg.blockUntunneledTrafficCB.SetVisible(false)
	dlg.blockUntunneledTrafficCB.CheckedChanged().Attach(dlg.onBlockUntunneledTrafficCBCheckedChanged)

	walk.NewHSpacer(buttonsContainer)

	if dlg.saveButton, err = walk.NewPushButton(buttonsContainer); err != nil {
		return nil, err
	}
	dlg.saveButton.SetText(l18n.Sprintf("&Save"))
	dlg.saveButton.Clicked().Attach(dlg.onSaveButtonClicked)

	cancelButton, err := walk.NewPushButton(buttonsContainer)
	if err != nil {
		return nil, err
	}
	cancelButton.SetText(l18n.Sprintf("Cancel"))
	cancelButton.Clicked().Attach(dlg.Cancel)

	dlg.SetCancelButton(cancelButton)
	dlg.SetDefaultButton(dlg.saveButton)

	dlg.syntaxEdit.PrivateKeyChanged().Attach(dlg.onSyntaxEditPrivateKeyChanged)
	dlg.syntaxEdit.BlockUntunneledTrafficStateChanged().Attach(dlg.onBlockUntunneledTrafficStateChanged)
	dlg.syntaxEdit.SetText(dlg.config.ToWgQuick())

	// Insert a dummy label immediately preceding syntaxEdit to have screen readers read it.
	// Otherwise they fallback to "RichEdit Control".
	syntaxEditWnd := dlg.syntaxEdit.Handle()
	parentWnd := win.GetParent(syntaxEditWnd)
	labelWnd := win.CreateWindowEx(0,
		windows.StringToUTF16Ptr("STATIC"), windows.StringToUTF16Ptr(l18n.Sprintf("&Configuration:")),
		win.WS_CHILD|win.WS_GROUP|win.SS_LEFT, 0, 0, 0, 0,
		parentWnd, win.HMENU(^uintptr(0)), win.HINSTANCE(win.GetWindowLongPtr(parentWnd, win.GWLP_HINSTANCE)), nil)
	prevWnd := win.GetWindow(syntaxEditWnd, win.GW_HWNDPREV)
	nextWnd := win.GetWindow(syntaxEditWnd, win.GW_HWNDNEXT)
	win.SetWindowPos(labelWnd, prevWnd, 0, 0, 0, 0, win.SWP_NOSIZE|win.SWP_NOMOVE)
	win.SetWindowPos(syntaxEditWnd, labelWnd, 0, 0, 0, 0, win.SWP_NOSIZE|win.SWP_NOMOVE)
	win.SetWindowPos(nextWnd, syntaxEditWnd, 0, 0, 0, 0, win.SWP_NOSIZE|win.SWP_NOMOVE)

	if tunnel != nil {
		dlg.Starting().Attach(func() {
			dlg.syntaxEdit.SetFocus()
		})
	}

	disposables.Spare()

	return dlg, nil
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
	text := dlg.syntaxEdit.Text()
	dlg.syntaxEdit.SetText("")
	dlg.syntaxEdit.SetText(text)
}

func (dlg *EditDialog) onBlockUntunneledTrafficStateChanged(state int) {
	dlg.blockUntunneledTraficCheckGuard = true
	switch syntax.BlockState(state) {
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
		dlg.pubkeyEdit.SetText(l18n.Sprintf("(unknown)"))
	}
}

func (dlg *EditDialog) onSaveButtonClicked() {
	newName := dlg.nameEdit.Text()
	if newName == "" {
		showWarningCustom(dlg, l18n.Sprintf("Invalid name"), l18n.Sprintf("A name is required."))
		return
	}
	if !conf.TunnelNameIsValid(newName) {
		showWarningCustom(dlg, l18n.Sprintf("Invalid name"), l18n.Sprintf("Tunnel name ‘%s’ is invalid.", newName))
		return
	}
	newNameLower := strings.ToLower(newName)

	if newNameLower != strings.ToLower(dlg.config.Name) {
		existingTunnelList, err := manager.IPCClientTunnels()
		if err != nil {
			showWarningCustom(dlg, l18n.Sprintf("Unable to list existing tunnels"), err.Error())
			return
		}
		for _, tunnel := range existingTunnelList {
			if strings.ToLower(tunnel.Name) == newNameLower {
				showWarningCustom(dlg, l18n.Sprintf("Tunnel already exists"), l18n.Sprintf("Another tunnel already exists with the name ‘%s’.", newName))
				return
			}
		}
	}

	cfg, err := conf.FromWgQuick(dlg.syntaxEdit.Text(), newName)
	if err != nil {
		showErrorCustom(dlg, l18n.Sprintf("Unable to create new configuration"), err.Error())
		return
	}

	dlg.config = *cfg
	dlg.Accept()
}
