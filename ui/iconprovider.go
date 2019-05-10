/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"fmt"
	"github.com/lxn/walk"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/service"
	"path"
	"syscall"
)

type widthAndState struct {
	width int
	state service.TunnelState
}

type widthAndDllIdx struct {
	width int
	idx   int32
	dll   string
}

var cachedOverlayIconsForWidthAndState = make(map[widthAndState]*walk.Icon)

func iconWithOverlayForState(state service.TunnelState, size int) (icon *walk.Icon, err error) {
	icon = cachedOverlayIconsForWidthAndState[widthAndState{size, state}]
	if icon != nil {
		return
	}
	wireguardIcon, err := loadLogoIcon(size)
	if err != nil {
		return
	}
	iconSize := wireguardIcon.Size()
	bmp, err := walk.NewBitmapWithTransparentPixels(iconSize)
	if err != nil {
		return
	}
	defer bmp.Dispose()

	canvas, err := walk.NewCanvasFromImage(bmp)
	if err != nil {
		return
	}
	defer canvas.Dispose()

	err = canvas.DrawImage(wireguardIcon, walk.Point{})
	if err != nil {
		return
	}

	w := int(float64(iconSize.Width) * 0.65)
	h := int(float64(iconSize.Height) * 0.65)
	bounds := walk.Rectangle{iconSize.Width - w, iconSize.Height - h, w, h}
	overlayIcon, err := iconForState(state, bounds.Width)
	if err != nil {
		return
	}
	defer overlayIcon.Dispose()
	err = canvas.DrawImageStretched(overlayIcon, bounds)
	if err != nil {
		return
	}
	canvas.Dispose()

	icon, err = walk.NewIconFromBitmap(bmp)
	if err == nil {
		cachedOverlayIconsForWidthAndState[widthAndState{size, state}] = icon
	}
	return
}

var cachedIconsForWidthAndState = make(map[widthAndState]*walk.Icon)

func iconForState(state service.TunnelState, size int) (icon *walk.Icon, err error) {
	icon = cachedIconsForWidthAndState[widthAndState{size, state}]
	if icon != nil {
		return
	}
	switch state {
	case service.TunnelStarted:
		icon, err = loadSystemIcon("imageres", 101, size)
	case service.TunnelStopped:
		icon, err = walk.NewIconFromResourceWithSize("dot-gray.ico", walk.Size{size, size}) //TODO: replace with real icon
	default:
		icon, err = loadSystemIcon("shell32", 238, size) //TODO: this doesn't look that great overlayed on the app icon
	}
	if err == nil {
		cachedIconsForWidthAndState[widthAndState{size, state}] = icon
	}
	return
}

var cachedSystemIconsForWidthAndDllIdx = make(map[widthAndDllIdx]*walk.Icon)

func loadSystemIcon(dll string, index int32, size int) (icon *walk.Icon, err error) {
	icon = cachedSystemIconsForWidthAndDllIdx[widthAndDllIdx{size, index, dll}]
	if icon != nil {
		return
	}
	system32, err := windows.GetSystemDirectory()
	if err != nil {
		return
	}
	var hicon win.HICON
	ret := win.SHDefExtractIcon(windows.StringToUTF16Ptr(path.Join(system32, dll+".dll")), index, 0, &hicon, nil, uint32(size))
	if ret != 0 {
		return nil, fmt.Errorf("Unable to find icon %d of %s: %v", index, dll, syscall.Errno(ret))
	}
	icon, err = walk.NewIconFromHICON(hicon)
	if err == nil {
		cachedSystemIconsForWidthAndDllIdx[widthAndDllIdx{size, index, dll}] = icon
	}
	return
}

var cachedLogoIconsForWidth = make(map[int]*walk.Icon)

func loadLogoIcon(size int) (icon *walk.Icon, err error) {
	icon = cachedLogoIconsForWidth[size]
	if icon != nil {
		return
	}
	icon, err = walk.NewIconFromResourceWithSize("$wireguard.ico", walk.Size{size, size})
	if err == nil {
		cachedLogoIconsForWidth[size] = icon
	}
	return
}
