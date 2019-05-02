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
	"sort"
	"strings"
	"time"

	"github.com/lxn/walk"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/service"
)

type TunnelsPage struct {
	*walk.TabPage

	tunnelsView   *TunnelsView
	confView      *ConfView
	fillerButton  *walk.PushButton
	fillerHandler func()

	fillerContainer        *walk.Composite
	currentTunnelContainer *walk.Composite
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
	vlayout := walk.NewVBoxLayout()
	vlayout.SetMargins(walk.Margins{})
	tunnelsContainer.SetLayout(vlayout)

	//TODO: deal with remaining disposables in case the next line fails

	if tp.tunnelsView, err = NewTunnelsView(tunnelsContainer); err != nil {
		return nil, err
	}
	tp.tunnelsView.ItemActivated().Attach(tp.onTunnelsViewItemActivated)
	tp.tunnelsView.CurrentIndexChanged().Attach(tp.updateConfView)

	// HACK: Because of https://github.com/lxn/walk/issues/481
	// we need to put the ToolBar into its own Composite.
	toolBarContainer, _ := walk.NewComposite(tunnelsContainer)
	hlayout := walk.NewHBoxLayout()
	hlayout.SetMargins(walk.Margins{})
	toolBarContainer.SetLayout(hlayout)

	tunnelsToolBar, _ := walk.NewToolBarWithOrientationAndButtonStyle(toolBarContainer, walk.Horizontal, walk.ToolBarButtonImageOnly)
	imageSize := walk.Size{tp.DPI() / 6, tp.DPI() / 6} // Dividing by six is the same as dividing by 96 and multiplying by 16. TODO: Use dynamic DPI
	imageList, _ := walk.NewImageList(imageSize, walk.RGB(255, 255, 255))
	tunnelsToolBar.SetImageList(imageList)

	addMenu, _ := walk.NewMenu()
	tp.AddDisposable(addMenu)
	importAction := walk.NewAction()
	importAction.SetText("Import tunnel(s) from file...")
	importAction.Triggered().Attach(tp.onImport)
	addAction := walk.NewAction()
	addAction.SetText("Add empty tunnel")
	addAction.Triggered().Attach(tp.onAddTunnel)
	addMenu.Actions().Add(addAction)
	addMenu.Actions().Add(importAction)
	addMenuAction := walk.NewMenuAction(addMenu)
	addMenuActionIcon, _ := walk.NewIconFromResourceWithSize("add.ico", imageSize)
	addMenuActionImage, _ := walk.NewBitmapFromIcon(addMenuActionIcon, imageSize)
	addMenuAction.SetImage(addMenuActionImage)
	addMenuAction.SetToolTip(importAction.Text())
	addMenuAction.Triggered().Attach(tp.onImport)
	tunnelsToolBar.Actions().Add(addMenuAction)

	tunnelsToolBar.Actions().Add(walk.NewSeparatorAction())

	deleteAction := walk.NewAction()
	deleteActionIcon, _ := walk.NewIconFromResourceWithSize("delete.ico", imageSize)
	deleteActionImage, _ := walk.NewBitmapFromIcon(deleteActionIcon, imageSize)
	deleteAction.SetImage(deleteActionImage)
	deleteAction.SetToolTip("Remove selected tunnel(s)")
	deleteAction.Triggered().Attach(tp.onDelete)
	tunnelsToolBar.Actions().Add(deleteAction)

	tunnelsToolBar.Actions().Add(walk.NewSeparatorAction())

	exportAction := walk.NewAction()
	exportActionIcon, _ := walk.NewIconFromResourceWithSize("export.ico", imageSize)
	exportActionImage, _ := walk.NewBitmapFromIcon(exportActionIcon, imageSize)
	exportAction.SetImage(exportActionImage)
	exportAction.SetToolTip("Export all tunnels to zip...")
	exportAction.Triggered().Attach(tp.onExportTunnels)
	tunnelsToolBar.Actions().Add(exportAction)

	tp.currentTunnelContainer, _ = walk.NewComposite(tp)
	vlayout = walk.NewVBoxLayout()
	vlayout.SetMargins(walk.Margins{})
	tp.currentTunnelContainer.SetLayout(vlayout)
	tp.Layout().(interface{ SetStretchFactor(walk.Widget, int) error }).SetStretchFactor(tp.currentTunnelContainer, 10)

	tp.fillerContainer, _ = walk.NewComposite(tp)
	tp.fillerContainer.SetVisible(false)
	tp.fillerContainer.SetLayout(walk.NewHBoxLayout())
	tp.fillerContainer.Layout().SetMargins(walk.Margins{})
	tp.Layout().(interface{ SetStretchFactor(walk.Widget, int) error }).SetStretchFactor(tp.fillerContainer, 10)
	walk.NewHSpacer(tp.fillerContainer)
	tp.fillerButton, _ = walk.NewPushButton(tp.fillerContainer)
	buttonWidth := tp.DPI() * 2 //TODO: Use dynamic DPI
	tp.fillerButton.SetMinMaxSize(walk.Size{buttonWidth, 0}, walk.Size{buttonWidth, 0})
	tp.fillerButton.Clicked().Attach(func() {
		if tp.fillerHandler != nil {
			tp.fillerHandler()
		}
	})
	walk.NewHSpacer(tp.fillerContainer)

	//TODO: expose walk.TableView.itemCountChangedPublisher.Event()
	tp.tunnelsView.Property("ItemCount").Changed().Attach(tp.onTunnelsChanged)
	tp.onTunnelsChanged()
	tp.tunnelsView.SelectedIndexesChanged().Attach(tp.onSelectedTunnelsChanged)

	tp.confView, _ = NewConfView(tp.currentTunnelContainer)

	updateConfViewTicker := time.NewTicker(time.Second)
	tp.Disposing().Attach(updateConfViewTicker.Stop)
	go func() {
		for range updateConfViewTicker.C {
			tp.Synchronize(func() {
				tp.updateConfView()
			})
		}
	}()

	controlsContainer, _ := walk.NewComposite(tp.currentTunnelContainer)
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

func (tp *TunnelsPage) updateConfView() {
	if !tp.Visible() || !tp.currentTunnelContainer.Visible() {
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
		walk.MsgBox(tp.Form(), "Error", fmt.Sprintf("Could not import selected configuration: %v", lastErr), walk.MsgBoxIconWarning)
		return
	}

	// Add in reverse order so that the first one is selected.
	sort.Slice(unparsedConfigs, func(i, j int) bool {
		//TODO: use proper tunnel string sorting/comparison algorithm, as the other comments indicate too.
		return strings.Compare(unparsedConfigs[i].Name, unparsedConfigs[j].Name) > 0
	})

	existingTunnelList, err := service.IPCClientTunnels()
	if err != nil {
		walk.MsgBox(tp.Form(), "Error", fmt.Sprintf("Could not enumerate existing tunnels: %v", lastErr), walk.MsgBoxIconWarning)
		return
	}
	existingLowerTunnels := make(map[string]bool, len(existingTunnelList))
	for _, tunnel := range existingTunnelList {
		existingLowerTunnels[strings.ToLower(tunnel.Name)] = true
	}

	configCount := 0
	for _, unparsedConfig := range unparsedConfigs {
		if existingLowerTunnels[strings.ToLower(unparsedConfig.Name)] {
			lastErr = fmt.Errorf("Another tunnel already exists with the name ‘%s’", unparsedConfig.Name)
			continue
		}
		config, err := conf.FromWgQuick(unparsedConfig.Config, unparsedConfig.Name)
		if err != nil {
			lastErr = err
			continue
		}
		_, err = service.IPCClientNewTunnel(config)
		if err != nil {
			lastErr = err
			continue
		}
		configCount++
	}

	m, n := configCount, len(unparsedConfigs)
	switch {
	case n == 1 && m != n:
		walk.MsgBox(tp.Form(), "Error", fmt.Sprintf("Unable to import configuration: %v", lastErr), walk.MsgBoxIconWarning)
	case n == 1 && m == n:
		// nothing
	case m == n:
		walk.MsgBox(tp.Form(), "Imported tunnels", fmt.Sprintf("Imported %d tunnels", m), walk.MsgBoxOK)
	case m != n:
		walk.MsgBox(tp.Form(), "Imported tunnels", fmt.Sprintf("Imported %d of %d tunnels", m, n), walk.MsgBoxIconWarning)
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
	_, err := service.IPCClientNewTunnel(config)
	if err != nil {
		walk.MsgBox(tp.Form(), "Unable to create tunnel", err.Error(), walk.MsgBoxIconError)
	}

}

func (tp *TunnelsPage) deleteTunnel(tunnel *service.Tunnel) {
	err := tunnel.Delete()
	if err != nil {
		walk.MsgBox(tp.Form(), "Unable to delete tunnel", err.Error(), walk.MsgBoxIconError)
	}
}

// Handlers

func (tp *TunnelsPage) onTunnelsViewItemActivated() {
	go func() {
		globalState, err := service.IPCClientGlobalState()
		if err != nil || (globalState != service.TunnelStarted && globalState != service.TunnelStopped) {
			return
		}
		oldState, err := tp.tunnelsView.CurrentTunnel().Toggle()
		if err != nil {
			tp.Synchronize(func() {
				if oldState == service.TunnelUnknown {
					walk.MsgBox(tp.Form(), "Failed to determine tunnel state", err.Error(), walk.MsgBoxIconError)
				} else if oldState == service.TunnelStopped {
					walk.MsgBox(tp.Form(), "Failed to activate tunnel", err.Error(), walk.MsgBoxIconError)
				} else if oldState == service.TunnelStarted {
					walk.MsgBox(tp.Form(), "Failed to deactivate tunnel", err.Error(), walk.MsgBoxIconError)
				}
			})
			return
		}
	}()
}

func (tp *TunnelsPage) onEditTunnel() {
	tunnel := tp.tunnelsView.CurrentTunnel()
	if tunnel == nil {
		// Misfired event?
		return
	}

	if config := runTunnelEditDialog(tp.Form(), tunnel); config != nil {
		go func() {
			priorState, err := tunnel.State()
			tunnel.Delete()
			tunnel.WaitForStop()
			tunnel, err2 := service.IPCClientNewTunnel(config)
			if err == nil && err2 == nil && (priorState == service.TunnelStarting || priorState == service.TunnelStarted) {
				tunnel.Start()
			}
		}()
	}
}

func (tp *TunnelsPage) onAddTunnel() {
	if config := runTunnelEditDialog(tp.Form(), nil); config != nil {
		// Save new
		tp.addTunnel(config)
	}
}

func (tp *TunnelsPage) onDelete() {
	indices := tp.tunnelsView.SelectedIndexes()
	if len(indices) == 0 {
		return
	}

	var topic string
	if len(indices) > 1 {
		topic = fmt.Sprintf("%d tunnels", len(indices))
	} else {
		topic = fmt.Sprintf("‘%s’", tp.tunnelsView.model.tunnels[0].Name)
	}
	if walk.DlgCmdNo == walk.MsgBox(
		tp.Form(),
		fmt.Sprintf("Delete %s", topic),
		fmt.Sprintf("Are you sure you would like to delete %s? You cannot undo this action.", topic),
		walk.MsgBoxYesNo|walk.MsgBoxIconWarning) {
		return
	}
	for _, i := range indices {
		tp.deleteTunnel(&tp.tunnelsView.model.tunnels[i])
	}
}

func (tp *TunnelsPage) onImport() {
	tp.Form().Show() // Since the tray calls us sometimes, always make our parent visible.

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

func (tp *TunnelsPage) swapFiller(enabled bool) bool {
	//BUG: flicker switching with the currentTunnelContainer
	if tp.fillerContainer.Visible() == enabled {
		return enabled
	}
	tp.SetSuspended(true)
	tp.fillerContainer.SetVisible(enabled)
	tp.currentTunnelContainer.SetVisible(!enabled)
	tp.SetSuspended(false)
	return enabled
}

func (tp *TunnelsPage) onTunnelsChanged() {
	if tp.swapFiller(tp.tunnelsView.model.RowCount() == 0) {
		tp.fillerButton.SetText("Import tunnel(s) from file")
		tp.fillerHandler = tp.onImport
	}
}

func (tp *TunnelsPage) onSelectedTunnelsChanged() {
	indices := tp.tunnelsView.SelectedIndexes()
	if tp.swapFiller(len(indices) > 1) {
		tp.fillerButton.SetText(fmt.Sprintf("Delete %d tunnels", len(indices)))
		tp.fillerHandler = tp.onDelete
	}
}
