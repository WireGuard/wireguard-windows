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

type rectAndState struct {
	size  walk.Rectangle
	state service.TunnelState
}

type IconProvider struct {
	wireguardIcon        *walk.Icon
	imagesByRectAndState map[rectAndState]*walk.Bitmap
	iconsByState         map[service.TunnelState]*walk.Icon
	updateAvailabeImage  *walk.Bitmap
	scale                float64
}

func NewIconProvider(dpi int) (*IconProvider, error) {
	tsip := &IconProvider{
		imagesByRectAndState: make(map[rectAndState]*walk.Bitmap),
		iconsByState:         make(map[service.TunnelState]*walk.Icon),
		scale:                float64(dpi) / 96.0,
	}

	var err error

	var disposables walk.Disposables
	defer disposables.Treat()

	if tsip.wireguardIcon, err = walk.NewIconFromResource("$wireguard.ico"); err != nil {
		return nil, err
	}
	disposables.Add(tsip.wireguardIcon)

	disposables.Spare()
	return tsip, nil
}

func (tsip *IconProvider) Dispose() {
	if tsip.imagesByRectAndState != nil {
		for _, img := range tsip.imagesByRectAndState {
			img.Dispose()
		}
		tsip.imagesByRectAndState = nil
	}
	if tsip.iconsByState != nil {
		for _, icon := range tsip.iconsByState {
			icon.Dispose()
		}
		tsip.iconsByState = nil
	}
	if tsip.wireguardIcon != nil {
		tsip.wireguardIcon.Dispose()
		tsip.wireguardIcon = nil
	}
	if tsip.updateAvailabeImage != nil {
		tsip.updateAvailabeImage.Dispose()
		tsip.updateAvailabeImage = nil
	}
}

func (tsip *IconProvider) scaleForDPI(i int) int {
	return int(tsip.scale * float64(i))
}

func (tsip *IconProvider) UpdateAvailableImage() (*walk.Bitmap, error) {
	if tsip.updateAvailabeImage != nil {
		return tsip.updateAvailabeImage, nil
	}

	const size = 16 //TODO: this should use dynamic DPI, but we don't due to a walk bug with tab icons.
	redDot, err := walk.NewIconFromResourceWithSize("dot-red.ico", walk.Size{size, size})
	if err != nil {
		return nil, err
	}
	defer redDot.Dispose()
	img, err := walk.NewBitmapWithTransparentPixels(walk.Size{size, size})
	if err != nil {
		return nil, err
	}
	canvas, err := walk.NewCanvasFromImage(img)
	if err != nil {
		img.Dispose()
		return nil, err
	}
	defer canvas.Dispose()

	// This should be scaled for DPI but instead we do the opposite, due to a walk bug with tab icons.
	margin := int(3.0 - (tsip.scale-1.0)*3.0)
	if margin < 0 {
		margin = 0
	}
	rect := walk.Rectangle{margin, margin, size - margin*2, size - margin*2}

	if err := canvas.DrawImageStretched(redDot, rect); err != nil {
		img.Dispose()
		return nil, err
	}
	tsip.updateAvailabeImage = img
	return img, nil
}

func (tsip *IconProvider) ImageForTunnel(tunnel *service.Tunnel, size walk.Size) (*walk.Bitmap, error) {
	state, err := tunnel.State()
	if err != nil {
		return nil, err
	}

	return tsip.ImageForState(state, walk.Rectangle{0, 0, size.Width, size.Height})
}

func (tsip *IconProvider) ImageForState(state service.TunnelState, rect walk.Rectangle) (*walk.Bitmap, error) {
	key := rectAndState{rect, state}

	if img, ok := tsip.imagesByRectAndState[key]; ok {
		return img, nil
	}

	img, err := walk.NewBitmapWithTransparentPixels(rect.Size())
	if err != nil {
		return nil, err
	}

	canvas, err := walk.NewCanvasFromImage(img)
	if err != nil {
		return nil, err
	}
	defer canvas.Dispose()

	if err := tsip.PaintForState(state, canvas, rect); err != nil {
		return nil, err
	}

	tsip.imagesByRectAndState[key] = img

	return img, nil
}

func (tsip *IconProvider) IconWithOverlayForState(state service.TunnelState) (*walk.Icon, error) {
	if icon, ok := tsip.iconsByState[state]; ok {
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

	w := int(float64(size.Width) * 0.75)
	h := int(float64(size.Height) * 0.75)
	margin := tsip.scaleForDPI(2)
	bounds := walk.Rectangle{margin + size.Width - w, margin + size.Height - h, w, h}

	if err := tsip.PaintForState(state, canvas, bounds); err != nil {
		return nil, err
	}

	canvas.Dispose()

	icon, err := walk.NewIconFromBitmap(bmp)
	if err != nil {
		return nil, err
	}

	tsip.iconsByState[state] = icon

	return icon, nil
}

func (tsip *IconProvider) PaintForTunnel(tunnel *service.Tunnel, canvas *walk.Canvas, bounds walk.Rectangle) error {
	state, err := tunnel.State()
	if err != nil {
		return err
	}

	return tsip.PaintForState(state, canvas, bounds)
}

func (tsip *IconProvider) PaintForState(state service.TunnelState, canvas *walk.Canvas, bounds walk.Rectangle) error {
	iconSize := tsip.scaleForDPI(bounds.Height)
	var dot *walk.Icon
	var err error

	switch state {
	case service.TunnelStarted:
		dot, err = walk.NewIconFromResourceWithSize("dot-green.ico", walk.Size{iconSize, iconSize})

	case service.TunnelStopped:
		dot, err = walk.NewIconFromResourceWithSize("dot-gray.ico", walk.Size{iconSize, iconSize})

	default:
		dot, err = walk.NewIconFromResourceWithSize("dot-yellow.ico", walk.Size{iconSize, iconSize})
	}
	if err != nil {
		return err
	}
	defer dot.Dispose()

	b := bounds
	b.X += tsip.scaleForDPI(2)
	b.Y += tsip.scaleForDPI(2)
	b.Height -= tsip.scaleForDPI(4)
	b.Width = b.Height

	if err := canvas.DrawImageStretched(dot, b); err != nil {
		return err
	}

	return nil
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
