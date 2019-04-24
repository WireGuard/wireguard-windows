/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"fmt"
	"path"

	"github.com/lxn/walk"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"
)

var (
	systemIconAddTunnel,
	systemIconAddTunnelFromScratch,
	systemIconAddTunnelFromFile,
	systemIconDeleteTunnel,
	systemIconExportTunnels,
	systemIconSaveTunnelsToZip,
	_ *walk.Icon
)

func loadSystemIcon(dll string, index uint) (*walk.Icon, error) {
	system32, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	hicon := win.ExtractIcon(win.GetModuleHandle(nil), windows.StringToUTF16Ptr(path.Join(system32, dll+".dll")), int32(index))
	if hicon <= 1 {
		return nil, fmt.Errorf("Unable to find icon %d of %s", index, dll)
	}
	return walk.NewIconFromHICON(hicon)
}

func setIconOnAction(wb *walk.WindowBase, action *walk.Action, icon *walk.Icon) error {
	//TODO: this is an unholy hack. Fix walk!
	bitmap, err := walk.NewBitmapFromIcon(icon, walk.Size{32, 32})
	if err != nil {
		return err
	}
	wb.AddDisposable(bitmap)
	return action.SetImage(bitmap)
}

func loadSystemIcons() (err error) {
	//TODO: this should probably be in an object that is disposable instead of using globals like this

	systemIconAddTunnel, err = loadSystemIcon("shell32", 149)
	if err != nil {
		return
	}
	systemIconAddTunnelFromScratch, err = loadSystemIcon("imageres", 2)
	if err != nil {
		return
	}
	systemIconAddTunnelFromFile, err = loadSystemIcon("imageres", 3)
	if err != nil {
		return
	}
	systemIconDeleteTunnel, err = loadSystemIcon("shell32", 131)
	if err != nil {
		return
	}
	systemIconExportTunnels, err = loadSystemIcon("shell32", 45)
	if err != nil {
		return
	}
	systemIconSaveTunnelsToZip, err = loadSystemIcon("imageres", 165)
	if err != nil {
		return
	}

	return
}
