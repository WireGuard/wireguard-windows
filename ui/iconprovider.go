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

func iconWithOverlayForState(state service.TunnelState, size int) (*walk.Icon, error) {
	wireguardIcon, err := walk.NewIconFromResourceWithSize("$wireguard.ico", walk.Size{size, size})
	if err != nil {
		return nil, err
	}
	defer wireguardIcon.Dispose()
	iconSize := wireguardIcon.Size()
	bmp, err := walk.NewBitmapWithTransparentPixels(iconSize)
	if err != nil {
		return nil, err
	}
	defer bmp.Dispose()

	canvas, err := walk.NewCanvasFromImage(bmp)
	if err != nil {
		return nil, err
	}
	defer canvas.Dispose()

	if err := canvas.DrawImage(wireguardIcon, walk.Point{}); err != nil {
		return nil, err
	}

	w := int(float64(iconSize.Width) * 0.65)
	h := int(float64(iconSize.Height) * 0.65)
	bounds := walk.Rectangle{iconSize.Width - w, iconSize.Height - h, w, h}
	overlayIcon, err := iconForState(state, bounds.Width)
	if err != nil {
		return nil, err
	}
	defer overlayIcon.Dispose()
	if err := canvas.DrawImageStretched(overlayIcon, bounds); err != nil {
		return nil, err
	}
	canvas.Dispose()

	icon, err := walk.NewIconFromBitmap(bmp)
	if err != nil {
		return nil, err
	}
	return icon, nil
}

func iconForState(state service.TunnelState, size int) (icon *walk.Icon, err error) {
	switch state {
	case service.TunnelStarted:
		icon, err = loadSystemIcon("imageres", 101, size)

	case service.TunnelStopped:
		icon, err = walk.NewIconFromResourceWithSize("dot-gray.ico", walk.Size{size, size}) //TODO: replace with real icon

	default:
		icon, err = loadSystemIcon("shell32", 238, size) //TODO: this doesn't look that great overlayed on the app icon
	}
	return
}

func loadSystemIcon(dll string, index int32, size int) (*walk.Icon, error) {
	system32, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	var hicon win.HICON
	ret := win.SHDefExtractIcon(windows.StringToUTF16Ptr(path.Join(system32, dll+".dll")), index, 0, &hicon, nil, uint32(size))
	if ret != 0 {
		return nil, fmt.Errorf("Unable to find icon %d of %s due to error %d", index, dll, ret)
	}
	return walk.NewIconFromHICON(hicon)
}
