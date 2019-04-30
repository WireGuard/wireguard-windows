/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"github.com/lxn/walk"
	"golang.zx2c4.com/wireguard/windows/service"
	"math"
)

type rectAndState struct {
	size  walk.Rectangle
	state service.TunnelState
}

type IconProvider struct {
	baseIcon             *walk.Icon
	imagesByRectAndState map[rectAndState]*walk.Bitmap
	iconsByState         map[service.TunnelState]*walk.Icon
	stoppedBrush         *walk.SolidColorBrush
	startingBrush        *walk.SolidColorBrush
	startedBrush         *walk.SolidColorBrush
	stoppedPen           *walk.CosmeticPen
	startingPen          *walk.CosmeticPen
	startedPen           *walk.CosmeticPen
	updateAvailableImage *walk.Bitmap
	scale                float64
}

const (
	colorStopped         = 0xe1e1e1
	colorStarting        = 0xfec440
	colorStarted         = 0x01a405
	colorUpdateAvailable = 0xcb0110
)

func hexColor(c uint32) walk.Color {
	return walk.Color((((c >> 16) & 0xff) << 0) | (((c >> 8) & 0xff) << 8) | (((c >> 0) & 0xff) << 16))
}

func darkColor(c walk.Color) walk.Color {
	// Convert to HSL
	r, g, b := float64((uint32(c)>>16)&0xff)/255.0, float64((uint32(c)>>8)&0xff)/255.0, float64((uint32(c)>>0)&0xff)/255.0
	min := math.Min(r, math.Min(g, b))
	max := math.Max(r, math.Max(g, b))
	deltaMinMax := max - min
	l := (max + min) / 2
	h, s := 0.0, 0.0
	if deltaMinMax != 0 {
		if l < 0.5 {
			s = deltaMinMax / (max + min)
		} else {
			s = deltaMinMax / (2 - max - min)
		}
		deltaRed := (((max - r) / 6) + (deltaMinMax / 2)) / deltaMinMax
		deltaGreen := (((max - g) / 6) + (deltaMinMax / 2)) / deltaMinMax
		deltaBlue := (((max - b) / 6) + (deltaMinMax / 2)) / deltaMinMax
		if r == max {
			h = deltaBlue - deltaGreen
		} else if g == max {
			h = (1.0 / 3.0) + deltaRed - deltaBlue
		} else if b == max {
			h = (2.0 / 3.0) + deltaGreen - deltaRed
		}

		if h < 0 {
			h += 1
		} else if h > 1 {
			h -= 1
		}
	}

	// Darken by 10%
	l = math.Max(0, l-0.1)

	// Convert back to RGB
	if s == 0 {
		return walk.Color((uint32(l*255) << 16) | (uint32(l*255) << 8) | (uint32(l*255) << 0))
	}
	var v1, v2 float64
	if l < 0.5 {
		v2 = l * (1 + s)
	} else {
		v2 = (l + s) - (s * l)
	}
	v1 = 2.0*l - v2
	co := func(v1, v2, vH float64) float64 {
		if vH < 0 {
			vH += 1
		}
		if vH > 1 {
			vH -= 1
		}
		if (6.0 * vH) < 1 {
			return v1 + (v2-v1)*6.0*vH
		}
		if (2.0 * vH) < 1 {
			return v2
		}
		if (3.0 * vH) < 2 {
			return v1 + (v2-v1)*((2.0/3.0)-vH)*6.0
		}
		return v1
	}
	r, g, b = co(v1, v2, h+(1.0/3.0)), co(v1, v2, h), co(v1, v2, h-(1.0/3.0))
	return walk.Color((uint32(r*255) << 16) | (uint32(g*255) << 8) | (uint32(b*255) << 0))
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

	if tsip.baseIcon, err = walk.NewIconFromResourceId(1); err != nil {
		return nil, err
	}
	disposables.Add(tsip.baseIcon)

	if tsip.stoppedBrush, err = walk.NewSolidColorBrush(hexColor(colorStopped)); err != nil {
		return nil, err
	}
	disposables.Add(tsip.stoppedBrush)

	if tsip.startingBrush, err = walk.NewSolidColorBrush(hexColor(colorStarting)); err != nil {
		return nil, err
	}
	disposables.Add(tsip.startingBrush)

	if tsip.startedBrush, err = walk.NewSolidColorBrush(hexColor(colorStarted)); err != nil {
		return nil, err
	}
	disposables.Add(tsip.startedBrush)

	if tsip.stoppedPen, err = walk.NewCosmeticPen(walk.PenSolid, darkColor(hexColor(colorStopped))); err != nil {
		return nil, err
	}
	disposables.Add(tsip.stoppedPen)

	if tsip.startingPen, err = walk.NewCosmeticPen(walk.PenSolid, darkColor(hexColor(colorStarting))); err != nil {
		return nil, err
	}
	disposables.Add(tsip.startingPen)

	if tsip.startedPen, err = walk.NewCosmeticPen(walk.PenSolid, darkColor(hexColor(colorStarted))); err != nil {
		return nil, err
	}
	disposables.Add(tsip.startedPen)

	if tsip.updateAvailableImage, err = tsip.drawUpdateAvailableImage(16 /* This should be scaled for DPI, but isn't because of walk bug. */); err != nil {
		return nil, err
	}
	disposables.Add(tsip.updateAvailableImage)

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
	if tsip.stoppedBrush != nil {
		tsip.stoppedBrush.Dispose()
		tsip.stoppedBrush = nil
	}
	if tsip.startingBrush != nil {
		tsip.startingBrush.Dispose()
		tsip.startingBrush = nil
	}
	if tsip.startedBrush != nil {
		tsip.startedBrush.Dispose()
		tsip.startedBrush = nil
	}
	if tsip.stoppedPen != nil {
		tsip.stoppedPen.Dispose()
		tsip.stoppedPen = nil
	}
	if tsip.startingPen != nil {
		tsip.startingPen.Dispose()
		tsip.startingPen = nil
	}
	if tsip.startedPen != nil {
		tsip.startedPen.Dispose()
		tsip.startedPen = nil
	}
	if tsip.baseIcon != nil {
		tsip.baseIcon.Dispose()
		tsip.baseIcon = nil
	}
	if tsip.updateAvailableImage != nil {
		tsip.updateAvailableImage.Dispose()
		tsip.updateAvailableImage = nil
	}
}

func (tsip *IconProvider) scaleForDPI(i int) int {
	return int(tsip.scale * float64(i))
}

func (tsip *IconProvider) drawUpdateAvailableImage(size int) (*walk.Bitmap, error) {
	updateAvailableBrush, err := walk.NewSolidColorBrush(hexColor(colorUpdateAvailable))
	if err != nil {
		return nil, err
	}
	defer updateAvailableBrush.Dispose()
	updateAvailablePen, err := walk.NewCosmeticPen(walk.PenSolid, darkColor(hexColor(colorUpdateAvailable)))
	if err != nil {
		return nil, err
	}
	defer updateAvailablePen.Dispose()

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

	margin := 2 // This should be scaled for DPI but isn't, because of walk bug.
	rect := walk.Rectangle{margin, margin, size - margin*2, size - margin*2}

	if err := canvas.FillEllipse(updateAvailableBrush, rect); err != nil {
		img.Dispose()
		return nil, err
	}
	if err := canvas.DrawEllipse(updateAvailablePen, rect); err != nil {
		img.Dispose()
		return nil, err
	}
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

	size := tsip.baseIcon.Size()

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

	if err := canvas.DrawImage(tsip.baseIcon, walk.Point{}); err != nil {
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
	var (
		brush *walk.SolidColorBrush
		pen   *walk.CosmeticPen
	)

	switch state {
	case service.TunnelStarted:
		brush = tsip.startedBrush
		pen = tsip.startedPen

	case service.TunnelStopped:
		brush = tsip.stoppedBrush
		pen = tsip.stoppedPen

	default:
		brush = tsip.startingBrush
		pen = tsip.startingPen
	}

	b := bounds

	b.X += tsip.scaleForDPI(2)
	b.Y += tsip.scaleForDPI(2)
	b.Height -= tsip.scaleForDPI(4)
	b.Width = b.Height

	if err := canvas.FillEllipse(brush, b); err != nil {
		return err
	}
	if err := canvas.DrawEllipse(pen, b); err != nil {
		return err
	}

	return nil
}
