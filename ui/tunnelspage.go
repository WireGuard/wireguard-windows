/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"archive/zip"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lxn/walk"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/service"
)

type TunnelsPage struct {
	*walk.TabPage

	tunnelTracker          *TunnelTracker
	tunnelsView            *TunnelsView
	confView               *ConfView
	tunnelAddedPublisher   walk.StringEventPublisher
	tunnelDeletedPublisher walk.StringEventPublisher
}

func NewTunnelsPage() (*TunnelsPage, error) {
	var err error

	var disposables walk.Disposables
	defer disposables.Treat()

	tp := new(TunnelsPage)
	if tp.TabPage, err = walk.NewTabPage(); err != nil {
		return nil, err
	}
	disposables.Add(tp)

	tp.SetTitle("Tunnels")
	tp.SetLayout(walk.NewHBoxLayout())

	tunnelsContainer, _ := walk.NewComposite(tp)
	tunnelsContainer.SetLayout(walk.NewVBoxLayout())

	tp.tunnelsView, _ = NewTunnelsView(tunnelsContainer)
	tp.tunnelsView.ItemActivated().Attach(tp.onTunnelsViewItemActivated)
	tp.tunnelsView.CurrentIndexChanged().Attach(tp.updateConfView)

	// ToolBar actions
	{
		// HACK: Because of https://github.com/lxn/walk/issues/481
		// we need to put the ToolBar into its own Composite.
		toolBarContainer, _ := walk.NewComposite(tunnelsContainer)
		toolBarContainer.SetLayout(walk.NewHBoxLayout())

		tunnelsToolBar, _ := walk.NewToolBarWithOrientationAndButtonStyle(toolBarContainer, walk.Horizontal, walk.ToolBarButtonImageOnly)
		imageList, _ := walk.NewImageList(walk.Size{32, 32}, 0)
		tunnelsToolBar.SetImageList(imageList)

		importAction := walk.NewAction()
		importAction.SetText("Import tunnels from file...")
		setIconOnAction(tp.AsWindowBase(), importAction, systemIconAddTunnelFromFile)
		importAction.Triggered().Attach(tp.onImport)

		addAction := walk.NewAction()
		addAction.SetText("Add empty tunnel")
		setIconOnAction(tp.AsWindowBase(), addAction, systemIconAddTunnelFromScratch)
		addAction.Triggered().Attach(tp.onAddTunnel)

		exportTunnelsAction := walk.NewAction()
		exportTunnelsAction.SetText("Export tunnels to zip...")
		setIconOnAction(tp.AsWindowBase(), exportTunnelsAction, systemIconSaveTunnelsToZip)
		exportTunnelsAction.Triggered().Attach(tp.onExportTunnels)

		addMenu, _ := walk.NewMenu()
		tp.AddDisposable(addMenu)
		addMenu.Actions().Add(addAction)
		addMenu.Actions().Add(importAction)
		addMenuAction, _ := tunnelsToolBar.Actions().AddMenu(addMenu)
		setIconOnAction(tp.AsWindowBase(), addMenuAction, systemIconAddTunnel)

		deleteAction := walk.NewAction()
		tunnelsToolBar.Actions().Add(deleteAction)
		setIconOnAction(tp.AsWindowBase(), deleteAction, systemIconDeleteTunnel)
		deleteAction.Triggered().Attach(tp.onDelete)

		settingsMenu, _ := walk.NewMenu()
		tp.AddDisposable(settingsMenu)
		settingsMenu.Actions().Add(exportTunnelsAction)
		settingsMenuAction, _ := tunnelsToolBar.Actions().AddMenu(settingsMenu)
		setIconOnAction(tp.AsWindowBase(), settingsMenuAction, systemIconExportTunnels)
	}

	currentTunnelContainer, _ := walk.NewComposite(tp)
	currentTunnelContainer.SetLayout(walk.NewVBoxLayout())
	tp.Layout().(interface{ SetStretchFactor(walk.Widget, int) error }).SetStretchFactor(currentTunnelContainer, 10)

	tp.confView, _ = NewConfView(currentTunnelContainer)

	updateConfViewTicker := time.NewTicker(time.Second)
	tp.Disposing().Attach(updateConfViewTicker.Stop)
	go func() {
		for range updateConfViewTicker.C {
			tp.Synchronize(func() {
				tp.updateConfView()
			})
		}
	}()

	controlsContainer, _ := walk.NewComposite(currentTunnelContainer)
	controlsContainer.SetLayout(walk.NewHBoxLayout())
	controlsContainer.Layout().SetMargins(walk.Margins{})

	walk.NewHSpacer(controlsContainer)

	editTunnel, _ := walk.NewPushButton(controlsContainer)
	editTunnel.SetEnabled(false)
	tp.tunnelsView.CurrentIndexChanged().Attach(func() {
		editTunnel.SetEnabled(tp.tunnelsView.CurrentIndex() > -1)
	})
	editTunnel.SetText("Edit")
	editTunnel.Clicked().Attach(tp.onEditTunnel)

	tp.tunnelsView.SetCurrentIndex(0)

	disposables.Spare()

	return tp, nil
}

func (tp *TunnelsPage) TunnelTracker() *TunnelTracker {
	return tp.tunnelTracker
}

func (tp *TunnelsPage) SetTunnelTracker(tunnelTracker *TunnelTracker) {
	tp.tunnelTracker = tunnelTracker

	tp.confView.SetTunnelTracker(tunnelTracker)
}

func (tp *TunnelsPage) SetTunnelState(tunnel *service.Tunnel, state service.TunnelState) {
	tp.tunnelsView.SetTunnelState(tunnel, state)
}

func (tp *TunnelsPage) updateConfView() {
	if !tp.Visible() {
		return
	}

	tp.confView.SetTunnel(tp.tunnelsView.CurrentTunnel())
}

// importFiles tries to import a list of configurations.
func (tp *TunnelsPage) importFiles(paths []string) {
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
		walk.MsgBox(tp.Form(), "Error", fmt.Sprintf("Could not parse some files: %v", lastErr), walk.MsgBoxIconWarning)
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
		walk.MsgBox(tp.Form(), "Error", fmt.Sprintf("Could not parse some files: %v", lastErr), walk.MsgBoxIconWarning)
	case n == 1 && m == n:
		// TODO: Select tunnel in the list
	case m == n:
		walk.MsgBox(tp.Form(), "Imported tunnels", fmt.Sprintf("Imported %d tunnels", m), walk.MsgBoxOK)
	case m != n:
		walk.MsgBox(tp.Form(), "Imported tunnels", fmt.Sprintf("Imported %d of %d tunnels", m, n), walk.MsgBoxIconWarning)
	default:
		panic("unreachable case")
	}
}

func (tp *TunnelsPage) exportTunnels(filePath string) {
	writeFileWithOverwriteHandling(tp.Form(), filePath, func(file *os.File) error {
		writer := zip.NewWriter(file)

		for _, tunnel := range tp.tunnelsView.model.tunnels {
			cfg, err := tunnel.StoredConfig()
			if err != nil {
				return fmt.Errorf("onExportTunnels: tunnel.StoredConfig failed: %v", err)
			}

			w, err := writer.Create(tunnel.Name + ".conf")
			if err != nil {
				return fmt.Errorf("onExportTunnels: writer.Create failed: %v", err)
			}

			if _, err := w.Write(([]byte)(cfg.ToWgQuick())); err != nil {
				return fmt.Errorf("onExportTunnels: cfg.ToWgQuick failed: %v", err)
			}
		}

		return writer.Close()
	})
}

func (tp *TunnelsPage) addTunnel(config *conf.Config) {
	tunnel, err := service.IPCClientNewTunnel(config)
	if err != nil {
		walk.MsgBox(tp.Form(), "Unable to create tunnel", err.Error(), walk.MsgBoxIconError)
		return
	}

	model := tp.tunnelsView.model
	model.tunnels = append(model.tunnels, tunnel)
	model.PublishRowsReset()
	model.Sort(model.SortedColumn(), model.SortOrder())

	for i, t := range model.tunnels {
		if t.Name == tunnel.Name {
			tp.tunnelsView.SetCurrentIndex(i)
			break
		}
	}

	tp.confView.SetTunnel(&tunnel)

	tp.tunnelAddedPublisher.Publish(tunnel.Name)
}

func (tp *TunnelsPage) deleteTunnel(tunnel *service.Tunnel) {
	tunnel.Delete()

	model := tp.tunnelsView.model

	for i, t := range model.tunnels {
		if t.Name == tunnel.Name {
			model.tunnels = append(model.tunnels[:i], model.tunnels[i+1:]...)
			model.PublishRowsRemoved(i, i)
			break
		}
	}

	tp.tunnelDeletedPublisher.Publish(tunnel.Name)
}

func (tp *TunnelsPage) TunnelAdded() *walk.StringEvent {
	return tp.tunnelAddedPublisher.Event()
}

func (tp *TunnelsPage) TunnelDeleted() *walk.StringEvent {
	return tp.tunnelDeletedPublisher.Event()
}

// Handlers

func (tp *TunnelsPage) onTunnelsViewItemActivated() {
	if tp.tunnelTracker.InTransition() {
		return
	}

	var err error
	var title string
	tunnel := tp.tunnelsView.CurrentTunnel()
	activeTunnel := tp.tunnelTracker.ActiveTunnel()
	if tunnel != nil && activeTunnel != nil && tunnel.Name == activeTunnel.Name {
		err, title = tp.tunnelTracker.DeactivateTunnel(), "Deactivating tunnel failed"
	} else {
		err, title = tp.tunnelTracker.ActivateTunnel(tunnel), "Activating tunnel failed"
	}
	if err != nil {
		walk.MsgBox(tp.Form(), title, fmt.Sprintf("Error: %s", err.Error()), walk.MsgBoxIconError)
	}
}

func (tp *TunnelsPage) onEditTunnel() {
	tunnel := tp.tunnelsView.CurrentTunnel()
	if tunnel == nil {
		// Misfired event?
		return
	}

	if config := runTunnelConfigDialog(tp.Form(), tunnel); config != nil {
		// Delete old one
		tp.deleteTunnel(tunnel)

		// Save new one
		tp.addTunnel(config)
	}
}

func (tp *TunnelsPage) onAddTunnel() {
	if config := runTunnelConfigDialog(tp.Form(), nil); config != nil {
		// Save new
		tp.addTunnel(config)
	}
}

func (tp *TunnelsPage) onDelete() {
	currentTunnel := tp.tunnelsView.CurrentTunnel()
	if currentTunnel == nil {
		// Misfired event?
		return
	}

	if walk.DlgCmdNo == walk.MsgBox(
		tp.Form(),
		fmt.Sprintf(`Delete "%s"`, currentTunnel.Name),
		fmt.Sprintf(`Are you sure you want to delete "%s"?`, currentTunnel.Name),
		walk.MsgBoxYesNo|walk.MsgBoxIconWarning) {
		return
	}

	tp.deleteTunnel(currentTunnel)

	tp.tunnelDeletedPublisher.Publish(currentTunnel.Name)
}

func (tp *TunnelsPage) onImport() {
	dlg := walk.FileDialog{
		Filter: "Configuration Files (*.zip, *.conf)|*.zip;*.conf|All Files (*.*)|*.*",
		Title:  "Import tunnel(s) from file...",
	}

	if ok, _ := dlg.ShowOpenMultiple(tp.Form()); !ok {
		return
	}

	tp.importFiles(dlg.FilePaths)
}

func (tp *TunnelsPage) onExportTunnels() {
	dlg := walk.FileDialog{
		Filter: "Configuration ZIP Files (*.zip)|*.zip",
		Title:  "Export tunnels to zip...",
	}

	if ok, _ := dlg.ShowSave(tp.Form()); !ok {
		return
	}

	if !strings.HasSuffix(dlg.FilePath, ".zip") {
		dlg.FilePath += ".zip"
	}

	tp.exportTunnels(dlg.FilePath)
}
