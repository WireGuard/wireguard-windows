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
)

type IconProvider struct {
	wireguardIcon       *walk.Icon
	overlayIconsByState map[service.TunnelState]*walk.Icon
}

func NewIconProvider() (*IconProvider, error) {
	tsip := &IconProvider{overlayIconsByState: make(map[service.TunnelState]*walk.Icon)}
	var err error
	if tsip.wireguardIcon, err = walk.NewIconFromResource("$wireguard.ico"); err != nil {
		return nil, err
	}
	return tsip, nil
}

func (tsip *IconProvider) Dispose() {
	if tsip.overlayIconsByState != nil {
		for _, icon := range tsip.overlayIconsByState {
			icon.Dispose()
		}
		tsip.overlayIconsByState = nil
	}
	if tsip.wireguardIcon != nil {
		tsip.wireguardIcon.Dispose()
		tsip.wireguardIcon = nil
	}
}

func (tsip *IconProvider) IconWithOverlayForState(state service.TunnelState) (*walk.Icon, error) {
	if icon, ok := tsip.overlayIconsByState[state]; ok {
		return icon, nil
	}

	size := tsip.wireguardIcon.Size()

	bmp, err := walk.NewBitmapWithTransparentPixels(size)
	if err != nil {
		return nil, err
	}
	defer bmp.Dispose()

	canvas, err := walk.NewCanvasFromImage(bmp)
	if err != nil {
		return nil, err
	}
	defer canvas.Dispose()

	if err := canvas.DrawImage(tsip.wireguardIcon, walk.Point{}); err != nil {
		return nil, err
	}

	overlayIcon, err := tsip.IconForState(state)
	if err != nil {
		return nil, err
	}
	defer overlayIcon.Dispose()

	w := int(float64(size.Width) * 0.65)
	h := int(float64(size.Height) * 0.65)
	bounds := walk.Rectangle{size.Width - w, size.Height - h, w, h}

	if err := canvas.DrawImageStretched(overlayIcon, bounds); err != nil {
		return nil, err
	}
	canvas.Dispose()

	icon, err := walk.NewIconFromBitmap(bmp)
	if err != nil {
		return nil, err
	}
	tsip.overlayIconsByState[state] = icon
	return icon, nil
}

func (tsip *IconProvider) IconForState(state service.TunnelState) (icon *walk.Icon, err error) {
	switch state {
	case service.TunnelStarted:
		icon, err = loadSystemIcon("imageres", 101)

	case service.TunnelStopped:
		icon, err = walk.NewIconFromResource("dot-gray.ico") //TODO: replace with real icon

	default:
		icon, err = loadSystemIcon("shell32", 238) //TODO: this doesn't look that great overlayed on the app icon
	}
	return
}

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
