/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"archive/zip"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"time"

	"github.com/lxn/walk"
	"github.com/lxn/win"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/service"
	"golang.zx2c4.com/wireguard/windows/ui/syntax"
)

type ManageTunnelsWindow struct {
	*walk.MainWindow

	icon *walk.Icon

	tunnelsView *TunnelsView
	confView    *ConfView
}

func NewManageTunnelsWindow(icon *walk.Icon) (*ManageTunnelsWindow, error) {
	var err error

	mtw := &ManageTunnelsWindow{
		icon: icon,
	}
	mtw.MainWindow, err = walk.NewMainWindowWithName("WireGuard")
	if err != nil {
		return nil, err
	}

	return mtw, mtw.setup()
}

func (mtw *ManageTunnelsWindow) setup() error {
	mtw.SetIcon(mtw.icon)
	mtw.SetSize(walk.Size{900, 600})
	mtw.SetLayout(walk.NewVBoxLayout())
	mtw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		// "Close to tray" instead of exiting application
		onQuit()
	})

	splitter, _ := walk.NewHSplitter(mtw)
	splitter.SetSuspended(true)
	defer func() {
		splitter.SetSuspended(false)
	}()

	tunnelsContainer, _ := walk.NewComposite(splitter)
	tunnelsContainer.SetLayout(walk.NewVBoxLayout())

	mtw.tunnelsView, _ = NewTunnelsView(tunnelsContainer)
	mtw.tunnelsView.ItemActivated().Attach(mtw.onEditTunnel)
	mtw.tunnelsView.CurrentIndexChanged().Attach(mtw.updateConfView)

	// ToolBar actions
	{
		// HACK: Because of https://github.com/lxn/walk/issues/481
		// we need to put the ToolBar into its own Composite.
		toolBarContainer, _ := walk.NewComposite(tunnelsContainer)
		toolBarContainer.SetLayout(walk.NewHBoxLayout())

		tunnelsToolBar, _ := walk.NewToolBar(toolBarContainer)

		importAction := walk.NewAction()
		importAction.SetText("Import tunnels from file...")
		importAction.Triggered().Attach(mtw.onImport)

		addAction := walk.NewAction()
		addAction.SetText("Add empty tunnel")
		addAction.Triggered().Attach(mtw.onAddTunnel)

		exportLogAction := walk.NewAction()
		exportLogAction.SetText("Export log to file...")
		// TODO: Triggered().Attach()

		exportTunnelAction := walk.NewAction()
		exportTunnelAction.SetText("Export tunnels to zip...")
		// TODO: Triggered().Attach()

		// TODO: Add this to the dispose array (AddDisposable)
		addMenu, _ := walk.NewMenu()
		addMenu.Actions().Add(addAction)
		addMenu.Actions().Add(importAction)
		addMenuAction, _ := tunnelsToolBar.Actions().AddMenu(addMenu)
		addMenuAction.SetText("Add")

		deleteAction := walk.NewAction()
		tunnelsToolBar.Actions().Add(deleteAction)
		deleteAction.SetText("Delete")
		deleteAction.Triggered().Attach(mtw.onDelete)

		settingsMenu, _ := walk.NewMenu()
		settingsMenu.Actions().Add(exportLogAction)
		settingsMenu.Actions().Add(exportTunnelAction)
		settingsMenuAction, _ := tunnelsToolBar.Actions().AddMenu(settingsMenu)
		settingsMenuAction.SetText("Export")
	}

	currentTunnelContainer, _ := walk.NewComposite(splitter)
	currentTunnelContainer.SetLayout(walk.NewVBoxLayout())

	mtw.confView, _ = NewConfView(currentTunnelContainer)
	go func() {
		// TODO: teardown in Dispose()
		t := time.NewTicker(time.Second)
		for range t.C {
			mtw.updateConfView()
		}
	}()

	// TODO: Find a better place for this?
	// logfile, err := service.IPCClientLogFilePath()
	// var logger *ringlogger.Ringlogger
	// if err == nil {
	// 	logger, err = ringlogger.NewRinglogger(logfile, "GUI")
	// }
	// if err != nil {
	// 	walk.MsgBox(nil, "Unable to initialize logging", fmt.Sprintf("%v\n\nFile: %s", err, logfile), walk.MsgBoxIconError)
	// 	return err
	// }
	// NewLogView(currentTunnelContainer, logger)

	controlsContainer, _ := walk.NewComposite(currentTunnelContainer)
	controlsContainer.SetLayout(walk.NewHBoxLayout())
	controlsContainer.Layout().SetMargins(walk.Margins{})

	walk.NewHSpacer(controlsContainer)

	// TODO: Disable when nothing is selected
	editTunnel, _ := walk.NewPushButton(controlsContainer)
	editTunnel.SetText("Edit")
	editTunnel.Clicked().Attach(mtw.onEditTunnel)

	return nil
}

func (mtw *ManageTunnelsWindow) Show() {
	mtw.MainWindow.Show()
	// TODO: Upstream lxn/walk has VisibleChanged()
	mtw.updateConfView()
	win.SetForegroundWindow(mtw.Handle())
	win.BringWindowToTop(mtw.Handle())
}

func (mtw *ManageTunnelsWindow) SetTunnelState(tunnel *service.Tunnel, state service.TunnelState) {
	mtw.tunnelsView.SetTunnelState(tunnel, state)
	// mtw.confView.SetTunnelState(tunnel, state)
}

func (mtw *ManageTunnelsWindow) updateConfView() {
	if !mtw.Visible() {
		return
	}

	currentTunnel := mtw.tunnelsView.CurrentTunnel()
	if currentTunnel == nil {
		// TODO: config must be non-nil right now
		// mtw.confView.SetConfiguration(nil)
		return
	}

	config, err := currentTunnel.RuntimeConfig()
	if err != nil {
		return
	}

	mtw.confView.SetConfiguration(&config)
}

func (mtw *ManageTunnelsWindow) runTunnelEdit(tunnel *service.Tunnel) *conf.Config {
	var (
		title  string
		name   string
		config conf.Config
	)

	if tunnel == nil {
		// Creating a new tunnel, create a new private key and use the default template
		title = "Create new tunnel"
		name = "New tunnel"
		pk, _ := conf.NewPrivateKey()
		config = conf.Config{Interface: conf.Interface{PrivateKey: *pk}}
	} else {
		title = "Edit tunnel"
		name = tunnel.Name
		config, _ = tunnel.RuntimeConfig()
	}

	dlg, _ := walk.NewDialog(mtw)
	dlg.SetIcon(mtw.icon)
	dlg.SetTitle(title)
	dlg.SetLayout(walk.NewGridLayout())
	// TODO: use size hints in layout elements to communicate the minimal width
	dlg.SetMinMaxSize(walk.Size{500, 400}, walk.Size{9999, 9999})
	dlg.Layout().(*walk.GridLayout).SetColumnStretchFactor(1, 3)
	dlg.Layout().SetSpacing(6)
	dlg.Layout().SetMargins(walk.Margins{18, 18, 18, 18})

	nameLabel, _ := walk.NewTextLabel(dlg)
	dlg.Layout().(*walk.GridLayout).SetRange(nameLabel, walk.Rectangle{0, 0, 1, 1})
	nameLabel.SetTextAlignment(walk.AlignHFarVCenter)
	nameLabel.SetText("Name:")

	nameEdit, _ := walk.NewLineEdit(dlg)
	dlg.Layout().(*walk.GridLayout).SetRange(nameEdit, walk.Rectangle{1, 0, 1, 1})
	// TODO: compute the next available tunnel name ?
	nameEdit.SetText(name)

	pubkeyLabel, _ := walk.NewTextLabel(dlg)
	dlg.Layout().(*walk.GridLayout).SetRange(pubkeyLabel, walk.Rectangle{0, 1, 1, 1})
	pubkeyLabel.SetTextAlignment(walk.AlignHFarVCenter)
	pubkeyLabel.SetText("Public key:")

	pubkeyEdit, _ := walk.NewLineEdit(dlg)
	dlg.Layout().(*walk.GridLayout).SetRange(pubkeyEdit, walk.Rectangle{1, 1, 1, 1})
	pubkeyEdit.SetReadOnly(true)
	pubkeyEdit.SetText("(unknown)")

	syntaxEdit, _ := syntax.NewSyntaxEdit(dlg)
	dlg.Layout().(*walk.GridLayout).SetRange(syntaxEdit, walk.Rectangle{0, 2, 2, 1})
	lastPrivate := ""
	syntaxEdit.PrivateKeyChanged().Attach(func(privateKey string) {
		if privateKey == lastPrivate {
			return
		}
		lastPrivate = privateKey
		key, _ := conf.NewPrivateKeyFromString(privateKey)
		if key != nil {
			pubkeyEdit.SetText(key.Public().String())
		} else {
			pubkeyEdit.SetText("(unknown)")
		}
	})
	syntaxEdit.SetText(config.ToWgQuick())

	buttonsContainer, _ := walk.NewComposite(dlg)
	dlg.Layout().(*walk.GridLayout).SetRange(buttonsContainer, walk.Rectangle{0, 3, 2, 1})
	buttonsContainer.SetLayout(walk.NewHBoxLayout())
	buttonsContainer.Layout().SetMargins(walk.Margins{})

	walk.NewHSpacer(buttonsContainer)

	cancelButton, _ := walk.NewPushButton(buttonsContainer)
	cancelButton.SetText("Cancel")
	cancelButton.Clicked().Attach(dlg.Cancel)

	saveButton, _ := walk.NewPushButton(buttonsContainer)
	saveButton.SetText("Save")
	saveButton.Clicked().Attach(func() {
		// TODO: Save the current config
		dlg.Accept()
	})

	dlg.SetCancelButton(cancelButton)
	dlg.SetDefaultButton(saveButton)

	if dlg.Run() == walk.DlgCmdOK {
		// Save
	}

	return &conf.Config{}
}

// importFiles tries to import a list of configurations.
func (mtw *ManageTunnelsWindow) importFiles(paths []string) {
	type unparsedConfig struct {
		Name   string
		Config string
	}

	var (
		unparsedConfigs []unparsedConfig
		lastErr         error
	)

	// Note: other versions of WireGuard start with all .zip files, then all .conf files.
	// To reproduce that if needed, inverse-sort the array.
	for _, path := range paths {
		switch filepath.Ext(path) {
		case ".conf":
			textConfig, err := ioutil.ReadFile(path)
			if err != nil {
				lastErr = err
				continue
			}
			unparsedConfigs = append(unparsedConfigs, unparsedConfig{Name: strings.TrimSuffix(filepath.Base(path), ".conf"), Config: string(textConfig)})
		case ".zip":
			// 1 .conf + 1 error .zip edge case?
			r, err := zip.OpenReader(path)
			if err != nil {
				lastErr = err
				continue
			}

			for _, f := range r.File {
				if filepath.Ext(f.Name) != ".conf" {
					continue
				}

				rc, err := f.Open()
				if err != nil {
					lastErr = err
					continue
				}
				textConfig, err := ioutil.ReadAll(rc)
				rc.Close()
				if err != nil {
					lastErr = err
					continue
				}
				unparsedConfigs = append(unparsedConfigs, unparsedConfig{Name: strings.TrimSuffix(filepath.Base(f.Name), ".conf"), Config: string(textConfig)})
			}

			r.Close()
		}
	}

	if lastErr != nil || unparsedConfigs == nil {
		walk.MsgBox(mtw, "Error", fmt.Sprintf("Could not parse some files: %v", lastErr), walk.MsgBoxIconWarning)
		return
	}

	var configs []*conf.Config

	for _, unparsedConfig := range unparsedConfigs {
		config, err := conf.FromWgQuick(unparsedConfig.Config, unparsedConfig.Name)
		if err != nil {
			lastErr = err
			continue
		}
		service.IPCClientNewTunnel(config)
		configs = append(configs, config)
	}

	m, n := len(configs), len(unparsedConfigs)
	switch {
	case n == 1 && m != n:
		walk.MsgBox(mtw, "Error", fmt.Sprintf("Could not parse some files: %v", lastErr), walk.MsgBoxIconWarning)
	case n == 1 && m == n:
		// TODO: Select tunnel in the list
	case m == n:
		walk.MsgBox(mtw, "Imported tunnels", fmt.Sprintf("Imported %d tunnels", m), walk.MsgBoxOK)
	case m != n:
		walk.MsgBox(mtw, "Imported tunnels", fmt.Sprintf("Imported %d of %d tunnels", m, n), walk.MsgBoxIconWarning)
	default:
		panic("unreachable case")
	}
}

// Handlers

func (mtw *ManageTunnelsWindow) onEditTunnel() {
	currentTunnel := mtw.tunnelsView.CurrentTunnel()
	if currentTunnel == nil {
		// Misfired event?
		return
	}

	oldName := currentTunnel.Name
	if config := mtw.runTunnelEdit(currentTunnel); config != nil {
		// TODO: is there a tunnel rename call?
		if oldName != config.Name {
			// Delete old one
			// mtw.currentTunnel.Delete()
		}
		// Save new one
		// config.Create()
		// Update the currentTunnel to use the new config (careful to keep ordering)
	}
}

func (mtw *ManageTunnelsWindow) onAddTunnel() {
	if config := mtw.runTunnelEdit(nil); config != nil {
		// Save new
	}
}

func (mtw *ManageTunnelsWindow) onDelete() {
	currentTunnel := mtw.tunnelsView.CurrentTunnel()
	if currentTunnel == nil {
		// Misfired event?
		return
	}

	if walk.MsgBox(mtw, fmt.Sprintf(`Delete "%s"?`, currentTunnel.Name), fmt.Sprintf(`Are you sure you want to delete "%s"`, currentTunnel.Name), walk.MsgBoxYesNo|walk.MsgBoxIconWarning) != walk.DlgCmdOK {
		return
	}

	currentTunnel.Delete()
}

func (mtw *ManageTunnelsWindow) onImport() {
	dlg := &walk.FileDialog{}
	// dlg.InitialDirPath
	dlg.Filter = "Configuration Files (*.zip, *.conf)|*.zip;*.conf|All Files (*.*)|*.*"
	dlg.Title = "Import tunnel(s) from file..."

	if ok, _ := dlg.ShowOpenMultiple(mtw); !ok {
		return
	}

	mtw.importFiles(dlg.FilePaths)
}
