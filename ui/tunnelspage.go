/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"archive/zip"
	"fmt"
	"github.com/lxn/walk"
	"github.com/lxn/win"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/service"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unsafe"
)

type TunnelsPage struct {
	*walk.TabPage

	listView      *ListView
	listContainer walk.Container
	listToolbar   *walk.ToolBar
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

	tp.listContainer, _ = walk.NewComposite(tp)
	vlayout := walk.NewVBoxLayout()
	vlayout.SetMargins(walk.Margins{})
	vlayout.SetSpacing(0)
	tp.listContainer.SetLayout(vlayout)

	//TODO: deal with remaining disposables in case the next line fails

	if tp.listView, err = NewListView(tp.listContainer); err != nil {
		return nil, err
	}

	tp.currentTunnelContainer, _ = walk.NewComposite(tp)
	vlayout = walk.NewVBoxLayout()
	vlayout.SetMargins(walk.Margins{})
	tp.currentTunnelContainer.SetLayout(vlayout)

	tp.fillerContainer, _ = walk.NewComposite(tp)
	tp.fillerContainer.SetVisible(false)
	hlayout := walk.NewHBoxLayout()
	hlayout.SetMargins(walk.Margins{})
	tp.fillerContainer.SetLayout(hlayout)
	tp.fillerButton, _ = walk.NewPushButton(tp.fillerContainer)
	buttonWidth := tp.DPI() * 2 //TODO: Use dynamic DPI
	tp.fillerButton.SetMinMaxSize(walk.Size{buttonWidth, 0}, walk.Size{buttonWidth, 0})
	tp.fillerButton.Clicked().Attach(func() {
		if tp.fillerHandler != nil {
			tp.fillerHandler()
		}
	})

	tp.confView, _ = NewConfView(tp.currentTunnelContainer)

	controlsContainer, _ := walk.NewComposite(tp.currentTunnelContainer)
	controlsContainer.SetLayout(walk.NewHBoxLayout())
	controlsContainer.Layout().SetMargins(walk.Margins{})

	walk.NewHSpacer(controlsContainer)

	editTunnel, _ := walk.NewPushButton(controlsContainer)
	editTunnel.SetEnabled(false)
	tp.listView.CurrentIndexChanged().Attach(func() {
		editTunnel.SetEnabled(tp.listView.CurrentIndex() > -1)
	})
	editTunnel.SetText("Edit")
	editTunnel.Clicked().Attach(tp.onEditTunnel)

	disposables.Spare()

	//TODO: expose walk.TableView.itemCountChangedPublisher.Event()
	tp.listView.Property("ItemCount").Changed().Attach(tp.onTunnelsChanged)
	tp.listView.SelectedIndexesChanged().Attach(tp.onSelectedTunnelsChanged)
	tp.listView.ItemActivated().Attach(tp.onTunnelsViewItemActivated)
	tp.listView.CurrentIndexChanged().Attach(tp.updateConfView)
	tp.listView.Load(false)
	tp.onTunnelsChanged()

	return tp, nil
}

func (tp *TunnelsPage) CreateToolbar() {
	if tp.listToolbar != nil {
		return
	}

	// HACK: Because of https://github.com/lxn/walk/issues/481
	// we need to put the ToolBar into its own Composite.
	toolBarContainer, _ := walk.NewComposite(tp.listContainer)
	hlayout := walk.NewHBoxLayout()
	hlayout.SetMargins(walk.Margins{})
	toolBarContainer.SetLayout(hlayout)

	tp.listToolbar, _ = walk.NewToolBarWithOrientationAndButtonStyle(toolBarContainer, walk.Horizontal, walk.ToolBarButtonImageBeforeText)
	imageSize := walk.Size{tp.DPI() / 6, tp.DPI() / 6} // Dividing by six is the same as dividing by 96 and multiplying by 16. TODO: Use dynamic DPI
	imageList, _ := walk.NewImageList(imageSize, walk.RGB(0, 0, 0))
	tp.listToolbar.SetImageList(imageList)

	addMenu, _ := walk.NewMenu()
	tp.AddDisposable(addMenu)
	importAction := walk.NewAction()
	importAction.SetText("Import tunnel(s) from file...")
	importActionIcon, _ := loadSystemIcon("imageres", 3)
	importActionImage, _ := walk.NewBitmapFromIcon(importActionIcon, imageSize)
	importAction.SetImage(importActionImage)
	importAction.SetShortcut(walk.Shortcut{walk.ModControl, walk.KeyO})
	importAction.Triggered().Attach(tp.onImport)
	addAction := walk.NewAction()
	addAction.SetText("Add empty tunnel")
	addActionIcon, _ := loadSystemIcon("imageres", 2)
	addActionImage, _ := walk.NewBitmapFromIcon(addActionIcon, imageSize)
	addAction.SetImage(addActionImage)
	addAction.SetShortcut(walk.Shortcut{walk.ModControl, walk.KeyN})
	addAction.Triggered().Attach(tp.onAddTunnel)
	addMenu.Actions().Add(importAction)
	addMenu.Actions().Add(addAction)
	addMenuAction := walk.NewMenuAction(addMenu)
	addMenuActionIcon, _ := loadSystemIcon("shell32", 149)
	addMenuActionImage, _ := walk.NewBitmapFromIcon(addMenuActionIcon, imageSize)
	addMenuAction.SetImage(addMenuActionImage)
	addMenuAction.SetText("Add Tunnel")
	addMenuAction.SetToolTip(importAction.Text())
	addMenuAction.Triggered().Attach(tp.onImport)
	tp.listToolbar.Actions().Add(addMenuAction)

	tp.listToolbar.Actions().Add(walk.NewSeparatorAction())

	deleteAction := walk.NewAction()
	deleteActionIcon, _ := loadSystemIcon("shell32", 131)
	deleteActionImage, _ := walk.NewBitmapFromIcon(deleteActionIcon, imageSize)
	deleteAction.SetImage(deleteActionImage)
	deleteAction.SetShortcut(walk.Shortcut{0, walk.KeyDelete})
	deleteAction.SetToolTip("Remove selected tunnel(s)")
	deleteAction.Triggered().Attach(tp.onDelete)
	tp.listToolbar.Actions().Add(deleteAction)
	tp.listToolbar.Actions().Add(walk.NewSeparatorAction())

	exportAction := walk.NewAction()
	exportActionIcon, _ := loadSystemIcon("imageres", 165) // Or "shell32", 45?
	exportActionImage, _ := walk.NewBitmapFromIcon(exportActionIcon, imageSize)
	exportAction.SetImage(exportActionImage)
	exportAction.SetToolTip("Export all tunnels to zip...")
	exportAction.Triggered().Attach(tp.onExportTunnels)
	tp.listToolbar.Actions().Add(exportAction)

	var size win.SIZE
	tp.listToolbar.SendMessage(win.TB_GETIDEALSIZE, win.FALSE, uintptr(unsafe.Pointer(&size)))
	tp.listContainer.SetMinMaxSize(walk.Size{int(size.CX), 0}, walk.Size{int(size.CX), 0})
}

func (tp *TunnelsPage) updateConfView() {
	tp.confView.SetTunnel(tp.listView.CurrentTunnel())
}

func (tp *TunnelsPage) importFiles(paths []string) {
	go func() {
		syncedMsgBox := func(title string, message string, flags walk.MsgBoxStyle) {
			tp.Synchronize(func() {
				walk.MsgBox(tp.Form(), title, message, flags)
			})
		}
		type unparsedConfig struct {
			Name   string
			Config string
		}

		var (
			unparsedConfigs []unparsedConfig
			lastErr         error
		)

		for _, path := range paths {
			switch strings.ToLower(filepath.Ext(path)) {
			case ".conf":
				textConfig, err := ioutil.ReadFile(path)
				if err != nil {
					lastErr = err
					continue
				}
				unparsedConfigs = append(unparsedConfigs, unparsedConfig{Name: strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)), Config: string(textConfig)})
			case ".zip":
				// 1 .conf + 1 error .zip edge case?
				r, err := zip.OpenReader(path)
				if err != nil {
					lastErr = err
					continue
				}

				for _, f := range r.File {
					if strings.ToLower(filepath.Ext(f.Name)) != ".conf" {
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
					unparsedConfigs = append(unparsedConfigs, unparsedConfig{Name: strings.TrimSuffix(filepath.Base(f.Name), filepath.Ext(f.Name)), Config: string(textConfig)})
				}

				r.Close()
			}
		}

		if lastErr != nil || unparsedConfigs == nil {
			syncedMsgBox("Error", fmt.Sprintf("Could not import selected configuration: %v", lastErr), walk.MsgBoxIconWarning)
			return
		}

		// Add in reverse order so that the first one is selected.
		sort.Slice(unparsedConfigs, func(i, j int) bool {
			//TODO: use proper tunnel string sorting/comparison algorithm, as the other comments indicate too.
			return strings.Compare(unparsedConfigs[i].Name, unparsedConfigs[j].Name) > 0
		})

		existingTunnelList, err := service.IPCClientTunnels()
		if err != nil {
			syncedMsgBox("Error", fmt.Sprintf("Could not enumerate existing tunnels: %v", lastErr), walk.MsgBoxIconWarning)
			return
		}
		existingLowerTunnels := make(map[string]bool, len(existingTunnelList))
		for _, tunnel := range existingTunnelList {
			existingLowerTunnels[strings.ToLower(tunnel.Name)] = true
		}

		configCount := 0
		tp.listView.SetSuspendTunnelsUpdate(true)
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
		tp.listView.SetSuspendTunnelsUpdate(false)

		m, n := configCount, len(unparsedConfigs)
		switch {
		case n == 1 && m != n:
			syncedMsgBox("Error", fmt.Sprintf("Unable to import configuration: %v", lastErr), walk.MsgBoxIconWarning)
		case n == 1 && m == n:
			// nothing
		case m == n:
			syncedMsgBox("Imported tunnels", fmt.Sprintf("Imported %d tunnels", m), walk.MsgBoxIconInformation)
		case m != n:
			syncedMsgBox("Imported tunnels", fmt.Sprintf("Imported %d of %d tunnels", m, n), walk.MsgBoxIconWarning)
		}
	}()
}

func (tp *TunnelsPage) exportTunnels(filePath string) {
	writeFileWithOverwriteHandling(tp.Form(), filePath, func(file *os.File) error {
		writer := zip.NewWriter(file)

		for _, tunnel := range tp.listView.model.tunnels {
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

// Handlers

func (tp *TunnelsPage) onTunnelsViewItemActivated() {
	go func() {
		globalState, err := service.IPCClientGlobalState()
		if err != nil || (globalState != service.TunnelStarted && globalState != service.TunnelStopped) {
			return
		}
		oldState, err := tp.listView.CurrentTunnel().Toggle()
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
	tunnel := tp.listView.CurrentTunnel()
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
	indices := tp.listView.SelectedIndexes()
	if len(indices) == 0 {
		return
	}

	var topic string
	if len(indices) > 1 {
		topic = fmt.Sprintf("%d tunnels", len(indices))
	} else {
		topic = fmt.Sprintf("‘%s’", tp.listView.model.tunnels[0].Name)
	}
	if walk.DlgCmdNo == walk.MsgBox(
		tp.Form(),
		fmt.Sprintf("Delete %s", topic),
		fmt.Sprintf("Are you sure you would like to delete %s? You cannot undo this action.", topic),
		walk.MsgBoxYesNo|walk.MsgBoxIconWarning) {
		return
	}

	selectTunnelAfter := ""
	if len(indices) < len(tp.listView.model.tunnels) {
		sort.Ints(indices)
		max := 0
		for i, idx := range indices {
			if idx+1 < len(tp.listView.model.tunnels) && (i+1 == len(indices) || idx+1 != indices[i+1]) {
				max = idx + 1
			} else if idx-1 >= 0 && (i == 0 || idx-1 != indices[i-1]) {
				max = idx - 1
			}
		}
		selectTunnelAfter = tp.listView.model.tunnels[max].Name
	}
	if len(selectTunnelAfter) > 0 {
		tp.listView.selectTunnel(selectTunnelAfter)
	}

	tunnelsToDelete := make([]service.Tunnel, len(indices))
	for i, j := range indices {
		tunnelsToDelete[i] = tp.listView.model.tunnels[j]

	}
	go func() {
		tp.listView.SetSuspendTunnelsUpdate(true)
		var errors []error
		for _, tunnel := range tunnelsToDelete {
			err := tunnel.Delete()
			if err != nil && (len(errors) == 0 || errors[len(errors)-1].Error() != err.Error()) {
				errors = append(errors, err)
			}
		}
		tp.listView.SetSuspendTunnelsUpdate(false)
		if len(errors) > 0 {
			tp.listView.Synchronize(func() {
				if len(errors) == 1 {
					walk.MsgBox(tp.Form(), "Unable to delete tunnel", fmt.Sprintf("A tunnel was unable to be removed: %s", errors[0].Error()), walk.MsgBoxIconError)
				} else {
					walk.MsgBox(tp.Form(), "Unable to delete tunnels", fmt.Sprintf("%d tunnels were unable to be removed.", len(errors)), walk.MsgBoxIconError)
				}
			})
		}
	}()
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
	if tp.swapFiller(tp.listView.model.RowCount() == 0) {
		tp.fillerButton.SetText("Import tunnel(s) from file")
		tp.fillerHandler = tp.onImport
	}
}

func (tp *TunnelsPage) onSelectedTunnelsChanged() {
	indices := tp.listView.SelectedIndexes()
	if tp.swapFiller(len(indices) > 1) {
		tp.fillerButton.SetText(fmt.Sprintf("Delete %d tunnels", len(indices)))
		tp.fillerHandler = tp.onDelete
	}
}
